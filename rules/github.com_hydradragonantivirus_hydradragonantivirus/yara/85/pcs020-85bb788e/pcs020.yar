import "pe"
rule pcs020
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.20 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
	condition:
		$a0 at pe.entry_point
}