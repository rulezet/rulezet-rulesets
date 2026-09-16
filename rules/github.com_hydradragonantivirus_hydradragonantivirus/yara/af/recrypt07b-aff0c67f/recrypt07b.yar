rule recrypt07b
{
	meta:
		author = "PEiD"
		description = "RE-Crypt 0.7b -> Crudd/RET"
		group = "444"
		function = "0"
	strings:
		$a0 = { 55 E8 00 00 00 00 5D 8B 7C 24 04 56 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 89 7D 64 8B FE 81 E7 00 FF FF FF 81 C7 ?? 00 00 00 }
	condition:
		$a0
}