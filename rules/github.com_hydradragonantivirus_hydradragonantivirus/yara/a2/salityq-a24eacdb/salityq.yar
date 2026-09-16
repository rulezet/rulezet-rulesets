import "pe"
rule _SalityQ_
{
	meta:
		description = "Sality.Q"
	strings:
		$0 = {60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 0C 24 33 04 24 D1 E9 66 AB 58 E2 24 57 B8 FC 4F 00 00 29 04 24 C3 8B 2C 24 B9 18 10 00 00 81 ED 06 10 40 00 90 90 90 81 C1 E8 17 00 00 90 EB 91 FF E3 ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}