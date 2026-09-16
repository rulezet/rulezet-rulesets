import "pe"
rule _GX_Protector_12__GurueXe_
{
	meta:
		description = "G!X Protector 1.2 -> Guru.eXe"
	strings:
		$0 = {60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00}
	condition:
		$0 at pe.entry_point
}