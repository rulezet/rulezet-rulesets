import "pe"
rule pec134_40b1
{
	meta:
		author = "PEiD"
		description = "PECompact 1.34 - 1.40b1 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB F8 10 }
	condition:
		$a0 at pe.entry_point
}