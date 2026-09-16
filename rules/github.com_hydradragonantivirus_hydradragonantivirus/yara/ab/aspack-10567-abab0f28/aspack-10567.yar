rule aspack_10567
{
	meta:
		author = "PEiD"
		description = "ASPack 1.05b - 1.07b -> Alexey Solodovnikov"
		group = "105"
		function = "2"
	strings:
		$a0 = { 75 00 E9 }
	condition:
		$a0
}