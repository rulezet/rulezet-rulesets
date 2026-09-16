import "pe"
rule neolite2x
{
	meta:
		author = "PEiD"
		description = "Neolite 2.0 / 2.x -> Neoworx Inc."
		group = "130"
		function = "0"
	strings:
		$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }
	condition:
		$a0 at pe.entry_point
}