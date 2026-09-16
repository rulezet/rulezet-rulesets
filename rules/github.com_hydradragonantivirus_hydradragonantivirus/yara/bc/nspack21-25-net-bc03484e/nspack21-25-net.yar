import "pe"
rule nspack21_25_net
{
	meta:
		author = "PEiD"
		description = "nSPack 2.1 - 2.5 (.NET) -> North Star/Liu Xing Ping"
		group = "555"
		function = "0"
	strings:
		$a0 = { 8D 9C 1B 6C 0E 00 00 53 52 FF 55 10 FF 77 09 89 45 F4 FF 75 0C FF 77 05 FF 75 F8 FF 75 FC FF 75 08 56 53 50 E8 FE FB FF FF 83 C4 24 33 F6 85 C0 75 01 46 68 00 80 00 00 6A 00 FF 75 F4 FF 55 14 8B C6 5E 5B 5F C9 C3 B8 ?? ?? ?? ?? C3 83 7C 24 04 00 75 03 33 C0 C3 A1 6C 70 00 30 A3 70 5B 00 30 8B 0D 34 70 00 30 51 50 FF 74 24 0C 89 0D 6C 5B 00 30 68 ?? ?? ?? ?? E8 12 FF FF FF 83 C4 10 F7 D8 1B C0 F7 D8 C3 }
	condition:
		$a0 at pe.entry_point
}