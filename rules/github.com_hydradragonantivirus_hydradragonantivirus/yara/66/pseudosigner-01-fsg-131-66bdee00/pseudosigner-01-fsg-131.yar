import "pe"
rule _PseudoSigner_01_FSG_131_
{
	meta:
		description = "PseudoSigner 0.1 [FSG 1.31"
	strings:
		$0 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9}
		$1 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}