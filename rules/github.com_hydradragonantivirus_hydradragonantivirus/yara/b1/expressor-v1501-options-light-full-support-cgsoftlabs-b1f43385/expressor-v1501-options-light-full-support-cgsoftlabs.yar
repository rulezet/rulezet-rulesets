import "pe"
rule _eXPressor_v1501_Options__Light_Full_support_CGSoftLabs_
{
	meta:
		description = "eXPressor v1.5.0.1 (Options -> Light, Full support) CGSoftLabs"
	strings:
		$0 = {55 8B EC 81 EC ?? 02 00 00 53 56 57 83 A5 ?? FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35}
	condition:
		$0 at pe.entry_point
}