import "pe"
rule _NJoy_13__NEX_
{
	meta:
		description = "N-Joy 1.3 -> NEX"
	strings:
		$0 = {55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00}
	condition:
		$0 at pe.entry_point
}