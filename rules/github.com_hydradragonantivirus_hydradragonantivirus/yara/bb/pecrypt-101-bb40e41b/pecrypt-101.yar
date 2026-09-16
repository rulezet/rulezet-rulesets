import "pe"
rule _PECrypt_101_
{
	meta:
		description = "PE-Crypt 1.01"
	strings:
		$0 = {E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB 03 FF CD 20 56 57 55 89 A3 4B 20 00 00 8B EB 80 BB FA 1F 00 00 01 0F 84 D3 17 00 00 C6 83 FA 1F 00 00 01 80 BB 21 20 00 00 00 75 26 8B 83 07 20 00 00 53 2B D8 EB 02 CD 20 EB 03 FF}
	condition:
		$0 at pe.entry_point
}