import "pe"
rule _Upack_Patch__Dwing_
{
	meta:
		description = "Upack_Patch -> Dwing"
	strings:
		$0 = {81 3A 00 00 00 02 00 00 00 00}
	condition:
		$0 at pe.entry_point
}