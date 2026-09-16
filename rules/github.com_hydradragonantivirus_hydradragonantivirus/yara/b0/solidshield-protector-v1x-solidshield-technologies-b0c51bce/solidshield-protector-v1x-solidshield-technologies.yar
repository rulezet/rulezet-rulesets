import "pe"
rule _Solidshield_Protector_V1X__Solidshield_Technologies_
{
	meta:
		description = "Solidshield Protector V1.X -> Solidshield Technologies"
	strings:
		$0 = {68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 00 60 89 00 0A 00 00 00 46 33 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}