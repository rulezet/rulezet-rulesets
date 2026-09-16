import "pe"
rule _ASProtect_23_SKE_build_0426_Beta_
{
	meta:
		description = "ASProtect 2.3 SKE build 04.26 Beta"
	strings:
		$0 = {68 01 60 40 00 E8 01 00 00 00 C3 C3 0D 6C 65 3E 09 84 BB 91 89 38 D0 5A 1D 60 6D AF D5 51 2D A9 2F E1 62 D8 C1 5A 8D 6B 6E 94 A7 F9 1D 26 8C 8E FB 08 A8 7E 9D 3B 0C DF 14 5E 62 14 7D 78 D0 6E}
	condition:
		$0 at pe.entry_point
}