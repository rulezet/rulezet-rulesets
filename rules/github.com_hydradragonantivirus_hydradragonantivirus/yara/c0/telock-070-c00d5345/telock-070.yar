rule telock_070
{
	meta:
		author = "PEiD"
		description = "tElock 0.70 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 BD 10 ?? ?? C3 83 }
	condition:
		$a0
}