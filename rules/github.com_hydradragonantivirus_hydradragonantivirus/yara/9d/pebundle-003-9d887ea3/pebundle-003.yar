import "pe"
rule _PEBundle_003_
{
	meta:
		description = "PEBundle 0.03"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD 01 AD 42 24 40 00 01 AD A3 24 40 00 01 AD D7 24 40 00 E8 B5 01 00 00 FF B5 9A 20 40 00 FF B5 FC 20 40 00 E8 39 02 00 00 72 13 FF B5 96 20 40 00 FF B5 F8 20}
	condition:
		$0 at pe.entry_point
}