import "pe"
rule _MicroJoiner_v17__coban2k_
{
	meta:
		description = "MicroJoiner v1.7 -> coban2k"
	strings:
		$0 = {BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00}
	condition:
		$0 at pe.entry_point
}