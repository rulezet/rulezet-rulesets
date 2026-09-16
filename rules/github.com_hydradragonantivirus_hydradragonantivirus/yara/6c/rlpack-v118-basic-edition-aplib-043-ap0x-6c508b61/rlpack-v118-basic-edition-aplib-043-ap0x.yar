import "pe"
rule _RLPack_V118_Basic_Edition_aPlib_043___ap0x_
{
	meta:
		description = "RLPack V1.18 Basic Edition (aPlib 0.43)  -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74}
	condition:
		$0 at pe.entry_point
}