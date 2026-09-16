import "pe"
rule bldjnr15
{
	meta:
		author = "PEiD"
		description = "Blade Joiner 1.5"
		group = "303"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }
	condition:
		$a0 at pe.entry_point
}