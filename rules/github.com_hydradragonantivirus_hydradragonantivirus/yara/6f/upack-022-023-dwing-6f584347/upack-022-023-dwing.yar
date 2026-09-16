import "pe"
rule _Upack_022__023__Dwing_
{
	meta:
		description = "Upack 0.22 - 0.23 -> Dwing"
	strings:
		$0 = {6A 07 BE 88 01 40 00 AD}
	condition:
		$0 at pe.entry_point
}