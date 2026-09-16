import "pe"
rule _SecuPack_15_
{
	meta:
		description = "SecuPack 1.5"
	strings:
		$0 = {55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 00 E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 F0 33 C0 E8 46 EA FF FF 8B 45 F0 E8 D6 F2 FF FF 50 E8 0C FD FF FF}
	condition:
		$0 at pe.entry_point
}