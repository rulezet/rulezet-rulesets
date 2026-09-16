rule aspack_108x
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.x -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		$a0
}