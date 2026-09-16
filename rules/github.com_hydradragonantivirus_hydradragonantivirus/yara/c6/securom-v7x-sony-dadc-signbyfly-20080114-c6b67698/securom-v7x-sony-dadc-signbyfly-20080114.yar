import "pe"
rule _SecuROM_V7X__Sony_DADC__SignByfly__20080114_
{
	meta:
		description = "SecuROM V7.X -> Sony DADC * Sign.By.fly * 20080114"
	strings:
		$0 = {9C 9C 83 EC 1C C7 44 24 18 ?? ?? ?? ?? C7 44 24 14 BF 03 01 00 89 74 24 10 BE F0 ?? ?? ?? C1 4C 24 18 18 ?? 89 6C 24 0C 8B 2E 01 6C 24 18 ?? 83 C6 04 66 FF 4C 24 14 52 5A 75 ED 80 64 24 18 FE ?? 8B 74 24 1C C1 E1 00 8B 6C 24 18 89 74 24 18 8B 74 24 10 89 6C 24 1C C1 E2 00 8B 6C 24 0C 83 C4 18 9D ?? 74 12 81 04 24 ?? ?? ?? ?? ?? 81 04 24 C3 D1 FF 00 EB FA 6B 81 04 24 ?? ?? ?? ?? 0F AC F8 00 81 04 24 C2 04 00 3E FF 74 24 04 9D EB F5 EE 93 9D}
	condition:
		$0 at pe.entry_point
}