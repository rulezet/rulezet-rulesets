import "pe"
rule _PEBundle_005__Jeremy_Collake_
{
	meta:
		description = "PEBundle 0.05 -> Jeremy Collake"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD 8D 85 A8 22 40 00 50 FF 95 42 23 40 00 0B C0 0F 85 B5 01 00 00 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 4A 23 40 00 0B C0 0F 84 99 01 00 00 89 85 D0}
	condition:
		$0 at pe.entry_point
}