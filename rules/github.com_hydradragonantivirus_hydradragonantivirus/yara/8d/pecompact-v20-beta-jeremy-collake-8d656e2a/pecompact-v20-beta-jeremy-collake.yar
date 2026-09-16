import "pe"
rule _PECompact_v20_beta__Jeremy_Collake_
{
	meta:
		description = "PECompact v2.0 beta -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90}
	condition:
		$0 at pe.entry_point
}