import "pe"
rule _PECompact_134__140b1_
{
	meta:
		description = "PECompact 1.34 - 1.40b1"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 00 87 DD 8B 85 A6 80 40 00 01 85 03 80 40 00 66 C7 85 00 80 40 00 90 90 01 85 9E 80 40 00 BB F8 10 00 00 03 9D AA 80 40 00 03 9D A6 80 40 00}
	condition:
		$0 at pe.entry_point
}