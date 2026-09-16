import "pe"
rule _XComp_V098_LZSS__JoKo_
{
	meta:
		description = "XComp V0.98 (LZSS) -> JoKo"
	strings:
		$0 = {68 ?? ?? ?? 00 9C 60 E8 E5 02 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 4C ?? ?? 00 34 ?? ?? 00 00 00}
	condition:
		$0 at pe.entry_point
}