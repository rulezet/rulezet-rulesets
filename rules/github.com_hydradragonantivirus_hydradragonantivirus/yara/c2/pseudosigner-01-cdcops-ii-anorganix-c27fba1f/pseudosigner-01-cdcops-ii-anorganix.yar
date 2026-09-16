import "pe"
rule _PseudoSigner_01_CDCops_II__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [CD-Cops II] --> Anorganix"
	strings:
		$0 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9}
	condition:
		$0 at pe.entry_point
}