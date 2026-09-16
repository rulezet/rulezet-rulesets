import "pe"
rule _CrypKey_Instant_Stealth_50161_
{
	meta:
		description = "CrypKey Instant Stealth 5.0.161"
	strings:
		$0 = {E8 00 00 00 00 58 83 E8 05 50 5F 57 8B F7 81 EF A7 1F 00 00 83 C6 39 BA 00 00 00 00 8B DF B9 0B 00 00 00 8B 06 33 03 89 06 83 C6 04 83 C3 04 E2 F2 42 83 FA 05 74 02 EB E3 6A 11 B6 AC 0D 65 DF D4 35 20 31 19 67 C0 CB 2D BA 36 19 73 C5 DB 70}
	condition:
		$0 at pe.entry_point
}