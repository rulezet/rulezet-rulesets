rule pepack10
{
	meta:
		author = "PEiD"
		description = "PE Pack 1.0 -> ANAKiN"
		group = "154"
		function = "0"
	strings:
		$a0 = { 74 ?? E9 }
	condition:
		$a0
}