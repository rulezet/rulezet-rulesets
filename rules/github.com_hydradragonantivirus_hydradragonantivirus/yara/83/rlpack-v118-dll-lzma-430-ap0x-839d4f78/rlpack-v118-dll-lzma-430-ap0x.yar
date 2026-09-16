import "pe"
rule _RLPack_V118_Dll_LZMA_430__ap0x_
{
	meta:
		description = "RLPack V1.18 Dll (LZMA 4.30) -> ap0x"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF}
	condition:
		$0 at pe.entry_point
}