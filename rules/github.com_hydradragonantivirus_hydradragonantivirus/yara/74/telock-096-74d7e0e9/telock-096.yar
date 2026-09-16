rule telock_096
{
	meta:
		author = "PEiD"
		description = "tElock 0.96 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 59 E4 FF FF }
	condition:
		$a0
}