rule armd71
{
	meta:
		author = "PEiD"
		description = "Armadillo 1.71 - 2.6x -> Silicon Realms Toolworks"
		group = "104"
		function = "5"
	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
	condition:
		$a0
}