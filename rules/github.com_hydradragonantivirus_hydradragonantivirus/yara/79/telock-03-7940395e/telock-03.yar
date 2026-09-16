import "pe"
rule telock_03
{
	meta:
		author = "PEiD"
		description = "tElock 0.3 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 66 8B C0 8D 24 24 60 9C E8 ?? ?? ?? ?? 5D D1 4D 12 81 6D 2A 79 AD 6C 4D EB 02 ?? ?? 8D B5 EC 01 }
	condition:
		$a0 at pe.entry_point
}