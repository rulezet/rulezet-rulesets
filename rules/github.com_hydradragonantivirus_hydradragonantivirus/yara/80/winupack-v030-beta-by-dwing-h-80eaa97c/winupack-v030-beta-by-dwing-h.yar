rule _WinUpack_v030_beta__By_Dwing_h_
{
	meta:
		description = "WinUpack v0.30 beta -> By Dwing (h)"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00}
	condition:
		$0
}