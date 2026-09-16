import "pe"
rule _Scrunch_102_
{
	meta:
		description = "Scrunch 1.02"
	strings:
		$0 = {EB 13 73 43 65 66 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BB FF FF B4 4A CD 21 81 EB F0 1F 73 18 BA 2B 01 B9 0F 00 E9 79 01 4F 75 74 20 6F 66 20 6D 65 6D 6F 72 79 2E 07 8C D8 A3 D2 02 05 00 10 A3 58 01 8E C0 E8 B4 01 B9 00 FF FC BE 00}
	condition:
		$0 at pe.entry_point
}