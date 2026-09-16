import "pe"
rule _PKLITE32_v11__PKWare_
{
	meta:
		description = "PKLITE32 v1.1 -> PKWare"
	strings:
		$0 = {68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8}
	condition:
		$0 at pe.entry_point
}