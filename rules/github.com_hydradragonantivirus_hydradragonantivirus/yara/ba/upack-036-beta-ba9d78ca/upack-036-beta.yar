rule upack_036_beta
{
	meta:
		author = "PEiD"
		description = "Upack 0.36 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE E0 11 40 00 FF 36 E9 C3 00 00 00 48 01 ?? ?? ?? ?? ?? 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 36 00 04 }
	condition:
		$a0
}