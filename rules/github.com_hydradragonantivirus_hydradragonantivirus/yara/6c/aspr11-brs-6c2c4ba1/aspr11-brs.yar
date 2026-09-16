rule aspr11_brs
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1 brs -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E9 ?? 05 }
	condition:
		$a0
}