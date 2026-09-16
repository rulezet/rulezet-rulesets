import "pe"
rule aspack_104b
{
	meta:
		author = "PEiD"
		description = "ASPack 1.04b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 12 9D ?? ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
	condition:
		$a0 at pe.entry_point
}