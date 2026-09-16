import "pe"
rule pec14_h
{
	meta:
		author = "PEiD"
		description = "PECompact 1.4x or above -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }
	condition:
		$a0 at pe.entry_point
}