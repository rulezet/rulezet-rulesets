import "pe"
rule _LOCK98_V10028__keenvim_
{
	meta:
		description = "LOCK98 V1.00.28 -> keenvim"
	strings:
		$0 = {55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08}
	condition:
		$0 at pe.entry_point
}