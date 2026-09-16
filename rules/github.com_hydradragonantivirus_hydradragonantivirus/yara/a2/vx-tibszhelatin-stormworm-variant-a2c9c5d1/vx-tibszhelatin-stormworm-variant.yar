import "pe"
rule _VX_TibsZhelatin_StormWorm_variant_
{
	meta:
		description = "VX: Tibs/Zhelatin StormWorm variant"
	strings:
		$0 = {FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8}
	condition:
		$0 at pe.entry_point
}