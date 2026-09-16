import "pe"
rule _NoClip_41_
{
	meta:
		description = "NoClip 4.1"
	strings:
		$0 = {FF 26 00 02 9C 50 53 51 8C D8 A3 0C 01 FA 8E D0 FB 81 C4 00 01 FF 16 00 00 EB 01 A1 FF 16 00 00 74 03 E9 86 00 A1 0C 01 03 06 16 01 73 02 83 BF 03 C1 50 B8 4E 03 75 02 FF 1E 50 8B EC BF 70 01 E8 15 10 4F E8 38 10 56 EB 01 A1 B8 00 29 CD 21}
	condition:
		$0 at pe.entry_point
}