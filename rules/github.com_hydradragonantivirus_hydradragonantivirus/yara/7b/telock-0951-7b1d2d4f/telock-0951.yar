rule telock_0951
{
	meta:
		author = "PEiD"
		description = "tElock 0.95 build 1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 D5 E4 FF FF }
	condition:
		$a0
}