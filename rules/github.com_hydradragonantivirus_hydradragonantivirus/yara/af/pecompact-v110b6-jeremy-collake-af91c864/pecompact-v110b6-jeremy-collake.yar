import "pe"
rule _PECompact_v110b6__Jeremy_Collake_
{
	meta:
		description = "PECompact v1.10b6 -> Jeremy Collake"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7}
	condition:
		$0 at pe.entry_point
}