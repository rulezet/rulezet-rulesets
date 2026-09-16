import "pe"
rule _PECompact_v122__Jeremy_Collake_
{
	meta:
		description = "PECompact v1.22 -> Jeremy Collake"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08}
	condition:
		$0 at pe.entry_point
}