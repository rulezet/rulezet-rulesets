import "pe"
rule aspack_103b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.03b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
	condition:
		$a0 at pe.entry_point
}