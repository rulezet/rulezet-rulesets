rule petite21x
{
	meta:
		author = "PEiD"
		description = "PEtite 2.x -> Ian Luck"
		group = "159"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$a0
}