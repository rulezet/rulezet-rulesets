rule telock_071b7
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b7 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 48 11 ?? ?? C3 83 }
	condition:
		$a0
}