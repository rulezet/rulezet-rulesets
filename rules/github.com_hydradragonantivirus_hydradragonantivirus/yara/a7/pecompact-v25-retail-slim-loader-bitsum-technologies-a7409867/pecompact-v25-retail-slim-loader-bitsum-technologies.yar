import "pe"
rule _PECompact_v25_Retail_Slim_Loader__Bitsum_Technologies_
{
	meta:
		description = "PECompact v2.5 Retail (Slim Loader) -> Bitsum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00}
	condition:
		$0 at pe.entry_point
}