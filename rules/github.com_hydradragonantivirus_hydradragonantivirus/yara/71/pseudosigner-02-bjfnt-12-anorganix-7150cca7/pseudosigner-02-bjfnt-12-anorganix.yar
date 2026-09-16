import "pe"
rule _PseudoSigner_02_BJFNT_12__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [.BJFNT 1.2] --> Anorganix"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00}
	condition:
		$0 at pe.entry_point
}