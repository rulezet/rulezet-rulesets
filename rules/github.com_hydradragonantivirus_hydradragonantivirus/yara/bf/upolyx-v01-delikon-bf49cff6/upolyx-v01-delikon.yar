import "pe"
rule _UPolyX_V01__Delikon_
{
	meta:
		description = "UPolyX V0.1 -> Delikon"
	strings:
		$0 = {E2 ?? FF ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}