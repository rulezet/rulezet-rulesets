import "pe"
rule _RLPack_120_Basic_Edition_waPLib_043__ap0x_
{
	meta:
		description = "RLPack 1.20 Basic Edition w/aPLib 0.43 -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00}
	condition:
		$0 at pe.entry_point
}