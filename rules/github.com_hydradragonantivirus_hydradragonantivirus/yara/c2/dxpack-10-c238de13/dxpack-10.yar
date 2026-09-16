import "pe"
rule _DxPack_10_
{
	meta:
		description = "DxPack 1.0"
	strings:
		$0 = {50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 ?? B8 40 ?? 03 ?? 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C C0 33 FE 8B 30 AC 30 D0}
	condition:
		$0 at pe.entry_point
}