import "pe"
rule xprot106
{
	meta:
		author = "PEiD"
		description = "Xtreme-Protector 1.06 -> Rafael Ahucha & Sergio Lara"
		group = "194"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 05 ?? ?? ?? E9 4A 01 ?? ?? 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF ?? ?? ?? 02 D2 75 05 }
	condition:
		$a0 at pe.entry_point
}