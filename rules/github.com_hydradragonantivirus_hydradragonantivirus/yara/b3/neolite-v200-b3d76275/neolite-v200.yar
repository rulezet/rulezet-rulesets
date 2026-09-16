import "pe"
rule _NeoLite_v200_
{
	meta:
		description = "NeoLite v2.00"
	strings:
		$0 = {8B 44 24 04 23 05 50 E8 83 C4 04 FE 05 0B C0}
		$1 = {E9 4E 65 6F 4C 69 74}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}