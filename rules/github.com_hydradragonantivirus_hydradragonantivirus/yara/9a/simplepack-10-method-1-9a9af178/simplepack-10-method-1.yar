rule simplepack_10_method_1
{
	meta:
		author = "PEiD"
		description = "SimplePack 1.0 Method 1 -> bagie[TMX]"
		group = "Fixed"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 5E ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 75 24 8D 83 1A ?? 00 00 50 6A 04 68 00 10 00 00 55 FF 93 6A ?? 00 00 09 C0 74 0B B8 00 ?? ?? 00 89 86 88 00 00 00 }
	condition:
		$a0
}