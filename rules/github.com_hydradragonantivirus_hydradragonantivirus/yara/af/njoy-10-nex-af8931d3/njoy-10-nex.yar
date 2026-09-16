import "pe"
rule _NJoy_10__NEX_
{
	meta:
		description = "N-Joy 1.0 -> NEX"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00}
	condition:
		$0 at pe.entry_point
}