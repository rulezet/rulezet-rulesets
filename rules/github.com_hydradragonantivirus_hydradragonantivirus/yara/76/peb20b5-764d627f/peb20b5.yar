import "pe"
rule peb20b5
{
	meta:
		author = "PEiD"
		description = "PEBundle 2.0b5 - 3.0x -> Jeremy Collake"
		group = "138"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }
	condition:
		$a0 at pe.entry_point
}