import "pe"
rule aspack_10803
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.03 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 4A 44 ?? BB 04 4A 44 ?? 03 DD 2B 9D B1 50 44 ?? 83 BD AC 50 44 ?? ?? 89 9D BB 4E }
	condition:
		$a0 at pe.entry_point
}