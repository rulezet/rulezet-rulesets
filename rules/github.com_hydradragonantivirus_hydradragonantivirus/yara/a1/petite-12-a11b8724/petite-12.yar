import "pe"
rule _Petite_12_
{
	meta:
		description = "Petite 1.2"
	strings:
		$0 = {66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00}
	condition:
		$0 at pe.entry_point
}