import "pe"
rule _PseudoSigner_02_CodeSafe_20_
{
	meta:
		description = "PseudoSigner 0.2 [CodeSafe 2.0"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85}
	condition:
		$0 at pe.entry_point
}