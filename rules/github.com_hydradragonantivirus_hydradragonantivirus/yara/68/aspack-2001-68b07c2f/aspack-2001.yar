rule aspack_2001
{
	meta:
		author = "PEiD"
		description = "ASPack 2.00.1 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 3B 05 ?? ?? EB 48 ?? ?? ?? ?? ?? ?? ?? ?? 87 DB 90 }
	condition:
		$a0
}