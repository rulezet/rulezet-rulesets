import "pe"
rule nspack22
{
	meta:
		author = "PEiD"
		description = "nSPack 2.2 -> North Star/Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 }
	condition:
		$a0 at pe.entry_point
}