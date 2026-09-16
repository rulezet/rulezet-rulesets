import "pe"
rule aspack_100b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.00b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
	condition:
		$a0 at pe.entry_point
}