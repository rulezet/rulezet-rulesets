import "pe"
rule _SCRAMB_120_
{
	meta:
		description = "SCRAMB 1.20"
	strings:
		$0 = {E8 00 00 5B 0E 1F 81 EB 50 02 8B C3 05 69 02 50 8B C8 03 D1 2B FA C3 56 34 00 D4 23 8B C3 05 00 02 89 87 93 04 8C 9F 95 04 33 C0 8E C0 8B D3 81 C2 86 02 B9 06 00 BE 04 00 26 8B 04 50 83 C6 02 83 F9 01 76 08 52 49 C3 43 76 88 99 11 26 A1 6C}
	condition:
		$0 at pe.entry_point
}