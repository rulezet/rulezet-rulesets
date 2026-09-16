import "pe"
rule _PECrypt_10_
{
	meta:
		description = "PE-Crypt 1.0"
	strings:
		$0 = {E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB 03 FF CD 20 56 57 55 89 A3 10 20 00 00 8B EB 80 BB BF 1F 00 00 01 0F 84 AB 17 00 00 C6 83 BF 1F 00 00 01 80 BB E6 1F 00 00 00 75 26 8B 83 CC 1F 00 00 53 2B D8 EB 02 CD 20 EB 03 FF}
	condition:
		$0 at pe.entry_point
}