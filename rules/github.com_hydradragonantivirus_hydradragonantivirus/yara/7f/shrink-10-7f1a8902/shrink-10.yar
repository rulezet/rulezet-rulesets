import "pe"
rule _Shrink_10_
{
	meta:
		description = "Shrink 1.0"
	strings:
		$0 = {50 9C FC BE 1F 01 BF 00 7E 57 B9 34 00 F3 A4 8B 0E 1C 01 BE 52 01 BF E8 80 F3 A4 C3 00 00 00 BE E8 80 8B 0E 1C 01 8A 26 1E 01 BF 00 01 57 AC 3A C4 74 10 8A D8 AA E2 F6 5B 9D 58 53 8B D9 8B F1 8B F9 C3 AC 0A C0 74 ED 49 86 C3 AA FE CB 75 FB}
	condition:
		$0 at pe.entry_point
}