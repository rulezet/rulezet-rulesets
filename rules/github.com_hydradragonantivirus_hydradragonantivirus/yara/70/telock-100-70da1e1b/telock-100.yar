rule telock_100
{
	meta:
		author = "PEiD"
		description = "tElock 1.00 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 E5 E2 FF FF }
	condition:
		$a0
}