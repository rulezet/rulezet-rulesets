import "pe"
rule _yodas_Protector_102b_Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector 1.02b-> Ashkbiz Danehkar"
	strings:
		$0 = {E8 03 00 00 00 EB 01}
	condition:
		$0 at pe.entry_point
}