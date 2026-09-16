import "pe"
rule _PECompact_110_beta_2_
{
	meta:
		description = "PECompact 1.10 beta 2"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 00 87 DD 8B 85 94 60 40 00 01 85 03 60 40 00 66 C7 85 00 60 40 00 90 90 BB 7F 0A 00 00 03 9D 98 60 40 00 03 9D 94 60 40 00 53 53 53 58 2D 6A}
	condition:
		$0 at pe.entry_point
}