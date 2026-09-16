import "pe"
rule _RLPack_120_Basic_Edition_wLZMA_430__ap0x_
{
	meta:
		description = "RLPack 1.20 Basic Edition w/LZMA 4.30 -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00}
	condition:
		$0 at pe.entry_point
}