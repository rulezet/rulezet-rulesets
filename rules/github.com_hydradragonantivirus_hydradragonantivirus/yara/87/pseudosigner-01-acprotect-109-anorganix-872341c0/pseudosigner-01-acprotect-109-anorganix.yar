import "pe"
rule _PseudoSigner_01_ACProtect_109__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [ACProtect 1.09] --> Anorganix"
	strings:
		$0 = {60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}