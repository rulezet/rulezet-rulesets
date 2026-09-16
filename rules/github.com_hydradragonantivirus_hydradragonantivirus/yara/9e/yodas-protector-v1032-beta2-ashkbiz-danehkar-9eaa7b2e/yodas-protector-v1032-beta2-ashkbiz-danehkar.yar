import "pe"
rule _Yodas_Protector_v1032_Beta2__Ashkbiz_Danehkar_
{
	meta:
		description = "Yoda's Protector v1.03.2 Beta2 -> Ashkbiz Danehkar"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00}
	condition:
		$0 at pe.entry_point
}