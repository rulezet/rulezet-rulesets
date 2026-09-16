import "pe"
rule _PEBundle_20x__24x__Jeremy_Collake_
{
	meta:
		description = "PEBundle 2.0x - 2.4x -> Jeremy Collake"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 00 87 DD 83 BD}
	condition:
		$0 at pe.entry_point
}