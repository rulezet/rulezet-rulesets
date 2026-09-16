import "pe"
rule _XPack_152__164_EXE_
{
	meta:
		description = "XPack 1.52 - 1.64 [EXE]"
	strings:
		$0 = {8B EC FA 33 C0 8E D0 BC 10 00 2E 8F 06 CD 03 2E 8F 06 D2 03 EB 01 9A 0E BB C2 03 53 5F EB 01 9A 17 8B E5 FB 48 D1 E8 EB 01 9A CE 9A 9C EB 01 9A 59 80 CD 01 51 9D EB 01 9A 1E 33 DB 8E DB C7 47 10 00 00 C7 47 12 00 00 0E 1F 8B EC EB 01 9A FA}
	condition:
		$0 at pe.entry_point
}