import "pe"
rule _ASPack_1061b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.061b -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED EA A8 43 00 B8 E4 A8 43 00 03 C5 2B 85 78 AD 43 00 89 85 84 AD 43 00 80 BD 6E AD 43}
	condition:
		$0 at pe.entry_point
}