rule telock_hsm7x
{
	meta:
		author = "PEiD"
		description = "tElock 0.7x - 0.84 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? C3 83 }
	condition:
		$a0
}