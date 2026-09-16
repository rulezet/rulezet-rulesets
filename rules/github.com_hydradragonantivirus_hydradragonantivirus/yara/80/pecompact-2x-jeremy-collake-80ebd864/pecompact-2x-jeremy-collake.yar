import "pe"
rule _PECompact_2x__Jeremy_Collake_
{
	meta:
		description = "PECompact 2.x -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}
	condition:
		$0 at pe.entry_point
}