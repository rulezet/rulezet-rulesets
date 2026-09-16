import "pe"
rule _PECompact_20x_Heuristic_Mode__Jeremy_Collake_
{
	meta:
		description = "PECompact 2.0x Heuristic Mode -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00}
	condition:
		$0 at pe.entry_point
}