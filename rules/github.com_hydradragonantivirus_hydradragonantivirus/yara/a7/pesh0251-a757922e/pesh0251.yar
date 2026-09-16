rule pesh0251
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.251 -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }
	condition:
		$a0
}