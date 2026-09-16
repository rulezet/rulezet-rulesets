import "pe"
rule _Themida__Oreans_Technologies_2004_
{
	meta:
		description = "Themida -> Oreans Technologies 2004"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8}
	condition:
		$0 at pe.entry_point
}