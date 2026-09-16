rule telock_099
{
	meta:
		author = "PEiD"
		description = "tElock 0.99 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 0D E4 FF FF }
	condition:
		$a0
}