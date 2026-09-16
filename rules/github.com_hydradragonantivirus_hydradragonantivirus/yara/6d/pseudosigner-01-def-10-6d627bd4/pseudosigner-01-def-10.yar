import "pe"
rule _PseudoSigner_01_DEF_10_
{
	meta:
		description = "PseudoSigner 0.1 [DEF 1.0"
	strings:
		$0 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9}
		$1 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}