rule telock_071
{
	meta:
		author = "PEiD"
		description = "tElock 0.71 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 ED 10 ?? ?? C3 83 }
	condition:
		$a0
}