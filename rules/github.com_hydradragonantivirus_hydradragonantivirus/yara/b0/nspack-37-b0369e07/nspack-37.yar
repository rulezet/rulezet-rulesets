rule nspack_37
{
	meta:
		author = "PEiD"
		description = "nSPack 3.7 -> North Star/ Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 8D ?? ?? FF FF 80 39 01 0F 84 42 02 00 00 C6 01 01 8B C5 2B 85 ?? ?? FF FF 89 85 ?? ?? FF FF 01 85 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 06 55 56 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 69 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 67 03 00 00 03 D9 50 53 E8 B0 02 00 00 5E 5D 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 34 01 13 8B 33 03 7B 04 57 51 53 FF B5 }
	condition:
		$a0
}