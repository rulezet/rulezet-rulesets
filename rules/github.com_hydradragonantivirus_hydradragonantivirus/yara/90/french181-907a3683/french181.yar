import "pe"
rule french181
{
	meta:
		author = "PEiD"
		description = "French Layor 1.81 -> Dr. rED mEAT"
		group = "123"
		function = "0"
	strings:
		$a0 = { EB 01 60 E8 00 00 00 00 5D 81 ED 08 10 40 00 E8 61 00 00 00 6A 00 FF 95 17 12 40 00 89 85 D3 11 40 00 8D 85 00 10 40 00 80 70 35 5C 66 81 B0 6A 00 00 00 7B 91 }
	condition:
		$a0 at pe.entry_point
}