import "pe"
rule xprot107
{
	meta:
		author = "PEiD"
		description = "Xtreme-Protector 1.07 -> Rafael Ahucha & Sergio Lara"
		group = "194"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 1E 00 00 00 E8 00 00 00 00 58 2D 16 00 00 00 B9 79 01 00 00 C6 00 E9 83 E9 05 89 48 01 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 }
	condition:
		$a0 at pe.entry_point
}