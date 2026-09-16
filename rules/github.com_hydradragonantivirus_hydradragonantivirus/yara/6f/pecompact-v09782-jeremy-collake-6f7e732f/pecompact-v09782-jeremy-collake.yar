import "pe"
rule _PECompact_v09782__Jeremy_Collake_
{
	meta:
		description = "PECompact v0.978.2 -> Jeremy Collake"
	strings:
		$0 = {EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85}
	condition:
		$0 at pe.entry_point
}