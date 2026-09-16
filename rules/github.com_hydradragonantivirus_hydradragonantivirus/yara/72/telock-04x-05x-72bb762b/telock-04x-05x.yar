import "pe"
rule telock_04x_05x
{
	meta:
		author = "PEiD"
		description = "tElock 0.4x - 0.5x -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 ?? 01 00 00 59 EB 01 }
	condition:
		$a0 at pe.entry_point
}