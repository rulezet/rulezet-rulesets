import "pe"
rule _yodas_Protector_v1033_exescrcom__Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector v1.03.3 (.exe,.scr,.com) -> Ashkbiz Danehkar"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75}
	condition:
		$0 at pe.entry_point
}