rule armd250b
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.50 beta -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$a0
}