import "pe"
rule _PEBundle_02__20x__Jeremy_Collake_
{
	meta:
		description = "PEBundle 0.2 - 2.0x -> Jeremy Collake"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95}
	condition:
		$0 at pe.entry_point
}