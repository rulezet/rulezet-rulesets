import "pe"
rule aspack_10801
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.01 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D 72 }
	condition:
		$a0 at pe.entry_point
}