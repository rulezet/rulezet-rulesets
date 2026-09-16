rule aspr1
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.0 -> Alexey Solodovnikov"
		group = "106"
		function = "0"
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		$a0
}