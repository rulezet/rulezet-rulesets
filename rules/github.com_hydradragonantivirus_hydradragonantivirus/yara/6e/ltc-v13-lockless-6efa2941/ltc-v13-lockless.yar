import "pe"
rule _LTC_v13__lockless_
{
	meta:
		description = "LTC v1.3 -> lockless"
	strings:
		$0 = {54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06}
	condition:
		$0 at pe.entry_point
}