rule obsidium1114
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.1.1.4 -> Obsidium Software"
		group = "133"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 3F 1D 00 00 }
	condition:
		$a0
}