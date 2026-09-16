import "pe"
rule _MSLRH_032a_fake_PECompact_14x__emadicius_
{
	meta:
		description = "MSLRH 0.32a (fake PECompact 1.4x) -> emadicius"
	strings:
		$0 = {EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A}
	condition:
		$0 at pe.entry_point
}