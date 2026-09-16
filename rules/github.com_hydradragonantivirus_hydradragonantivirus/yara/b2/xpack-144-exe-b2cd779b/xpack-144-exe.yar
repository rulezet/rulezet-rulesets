import "pe"
rule _XPack_144_EXE_
{
	meta:
		description = "XPack 1.44 [EXE]"
	strings:
		$0 = {8B EC EB 01 E8 B8 5A 03 FF E0 FA 33 C0 2E 21 06 01 01 8E D0 BC 10 00 2E 8F 06 9E 03 2E 8F 06 A3 03 EB 01 9A 0E BB 93 03 53 5F EB 01 9A 17 8B E5 FB 48 D1 E8 EB 01 9A CE 9A 9C EB 01 9A 59 80 CD 01 51 9D EB 01 9A 1E 33 DB 8E DB C7 47 10 00 00}
	condition:
		$0 at pe.entry_point
}