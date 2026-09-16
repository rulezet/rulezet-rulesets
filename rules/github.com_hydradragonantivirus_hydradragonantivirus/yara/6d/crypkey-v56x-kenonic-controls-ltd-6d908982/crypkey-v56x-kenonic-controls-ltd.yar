import "pe"
rule _CrypKey_V56X__Kenonic_Controls_Ltd_
{
	meta:
		description = "CrypKey V5.6.X -> Kenonic Controls Ltd."
	strings:
		$0 = {E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8}
	condition:
		$0 at pe.entry_point
}