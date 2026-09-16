rule upackgen
{
	meta:
		author = "PEiD"
		description = "Upack 0.1x - 0.2x beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 }
	condition:
		$a0
}