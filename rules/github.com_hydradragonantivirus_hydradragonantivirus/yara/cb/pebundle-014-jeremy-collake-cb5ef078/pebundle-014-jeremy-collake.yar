import "pe"
rule _PEBundle_014__Jeremy_Collake_
{
	meta:
		description = "PEBundle 0.14 -> Jeremy Collake"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 8C 33 40 00 0B C0 0F 84 DE 01 00 00 89 85 12 33 40 00 83 BD D0 32 40 00 01 74 0D 83 BD CC 32 40 00 01 74 2A}
	condition:
		$0 at pe.entry_point
}