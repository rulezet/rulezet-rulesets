import "pe"
rule _RLPack_117p_
{
	meta:
		description = "RLPack 1.17+"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? ?? 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3}
	condition:
		$0 at pe.entry_point
}