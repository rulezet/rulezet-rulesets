import "pe"
rule _Excalibur_103__forgot_
{
	meta:
		description = "Excalibur 1.03 -> forgot"
	strings:
		$0 = {E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00}
	condition:
		$0 at pe.entry_point
}