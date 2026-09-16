import "pe"
rule _MingWin32_v_h_
{
	meta:
		description = "MingWin32 v?.? (h)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55}
	condition:
		$0 at pe.entry_point
}