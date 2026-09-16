import "pe"
rule _PseudoSigner_01_CodeSafe_20_
{
	meta:
		description = "PseudoSigner 0.1 [CodeSafe 2.0"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}