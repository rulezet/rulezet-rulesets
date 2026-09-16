import "pe"
rule _ASPack_v21_
{
	meta:
		description = "ASPack v2.1"
	strings:
		$0 = {60 E9 3D}
	condition:
		$0 at pe.entry_point
}