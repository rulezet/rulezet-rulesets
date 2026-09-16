import "pe"
rule _Safengine_Licenseor_1720__Nooby_
{
	meta:
		description = "Safengine Licenseor 1.7.2.0 -> Nooby"
	strings:
		$0 = {E8 1B 00 00 00 53 00 61 00 66 00 65 00 6E 00 67 00 69 00 6E 00 65 00 20 00 4C 00 69 00 63 00 65}
	condition:
		$0 at pe.entry_point
}