import "pe"
rule _Stones_PE_Encryptor_v113__Stone_
{
	meta:
		description = "Stone's PE Encryptor v1.13 -> Stone"
	strings:
		$0 = {55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 ?? 3B 40 2B 95 2D ?? 3C 40 83 EA ?? 0B 89 95 36 3C 40 01 ?? 95 24 3C 40 01 ?? 95 28}
	condition:
		$0 at pe.entry_point
}