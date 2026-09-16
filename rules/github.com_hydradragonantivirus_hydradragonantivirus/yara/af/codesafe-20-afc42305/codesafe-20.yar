import "pe"
rule _CodeSafe_20_
{
	meta:
		description = "CodeSafe 2.0"
	strings:
		$0 = {83 3D 14 00 00 01 00 0F 84 08 00 00 00 A1 14 00 00 01 FF E0 C3 55 8B EC 83 EC 10 53 56 57 E8 C4 01 00 00 A1 98 00 00 01 2B 05 94 00 00 01 89 45 F4 A1 D4 00 00 01 03 05 C8 00 00 01 89 45 F8 A1 98 00 00 01 39 45 F8 0F 85 22 00 00 00 A1 A4 00}
	condition:
		$0 at pe.entry_point
}