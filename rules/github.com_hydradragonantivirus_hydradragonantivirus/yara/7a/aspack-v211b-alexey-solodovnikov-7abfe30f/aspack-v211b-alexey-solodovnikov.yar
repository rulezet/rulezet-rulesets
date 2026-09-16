import "pe"
rule _ASPack_v211b__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v2.11b -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00}
	condition:
		$0 at pe.entry_point
}