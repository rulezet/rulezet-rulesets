import "pe"
rule pcs029
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.29 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }
	condition:
		$a0 at pe.entry_point
}