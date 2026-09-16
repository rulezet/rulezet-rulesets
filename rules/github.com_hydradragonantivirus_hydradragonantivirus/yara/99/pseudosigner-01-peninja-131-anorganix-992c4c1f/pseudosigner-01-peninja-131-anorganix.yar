import "pe"
rule _PseudoSigner_01_PENinja_131__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [PENinja 1.31] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9}
	condition:
		$0 at pe.entry_point
}