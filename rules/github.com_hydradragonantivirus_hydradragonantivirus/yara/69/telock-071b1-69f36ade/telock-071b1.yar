rule telock_071b1
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b1 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 72 11 ?? ?? C3 83 }
	condition:
		$a0
}