import "pe"
rule _hyings_PEArmor_V076__hying_
{
	meta:
		description = "hying's PEArmor V0.76 -> hying"
	strings:
		$0 = {E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00}
	condition:
		$0 at pe.entry_point
}