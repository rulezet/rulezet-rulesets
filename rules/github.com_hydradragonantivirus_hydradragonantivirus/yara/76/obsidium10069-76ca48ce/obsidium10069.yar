rule obsidium10069
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.0.0.69 -> Obsidium Software"
		group = "133"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 A3 1C }
	condition:
		$a0
}