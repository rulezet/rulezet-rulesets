import "pe"
rule petite20
{
	meta:
		author = "PEiD"
		description = "PEtite 2.0 -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }
	condition:
		$a0 at pe.entry_point
}