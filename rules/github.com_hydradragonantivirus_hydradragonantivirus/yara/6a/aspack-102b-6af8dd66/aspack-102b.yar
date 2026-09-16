import "pe"
rule _ASPack_102b_
{
	meta:
		description = "ASPack 1.02b"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 2B 85 7D 7C 43 00 89 85 89 7C 43 00 80 BD 74 7C 43 00 00 75 15 FE 85 74 7C 43 00 E8 1D 00 00 00 E8 F7 01 00 00 E8 8E 02 00 00 8B 85 75 7C 43 00 03 85 89 7C 43 00 89 44 24 1C 61 FF}
	condition:
		$0 at pe.entry_point
}