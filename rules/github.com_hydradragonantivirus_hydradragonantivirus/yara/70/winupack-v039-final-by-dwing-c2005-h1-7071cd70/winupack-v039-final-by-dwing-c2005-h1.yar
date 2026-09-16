import "pe"
rule _WinUpack_v039_final__By_Dwing_c2005_h1_
{
	meta:
		description = "WinUpack v0.39 final -> By Dwing (c)2005 (h1)"
	strings:
		$0 = {BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}