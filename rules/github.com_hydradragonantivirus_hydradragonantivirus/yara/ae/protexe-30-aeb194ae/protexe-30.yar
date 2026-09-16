import "pe"
rule _ProtEXE_30_
{
	meta:
		description = "ProtEXE 3.0"
	strings:
		$0 = {9C 50 53 51 52 56 57 55 1E 06 FC B8 00 30 CD 21 84 C0 75 02 CD 20 A8 EB 04 00 EB FB 9A BA 21 00 EC 0C 02 EB 01 D0 EE BD 00 00 A8 EB 04 00 EB FB 9A BA 64 00 B0 AD EB 01 B1 EE B9 94 01 A8 EB 04 00 EB FB 9A 89 E8 34 00 2E 28 46 00 4D 49 74 02}
	condition:
		$0 at pe.entry_point
}