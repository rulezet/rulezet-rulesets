import "pe"
rule _RLPack_V118_Basic_Edition_aPLib_or_LZMA__ap0x_
{
	meta:
		description = "RLPack V1.18 Basic Edition (aPLib or LZMA) -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? 02 00 00 33 FF E8 ?? 01 00 00}
	condition:
		$0 at pe.entry_point
}