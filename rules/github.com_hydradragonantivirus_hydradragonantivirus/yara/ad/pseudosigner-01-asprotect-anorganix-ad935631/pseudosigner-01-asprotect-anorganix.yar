import "pe"
rule _PseudoSigner_01_ASProtect__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [ASProtect] --> Anorganix"
	strings:
		$0 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9}
	condition:
		$0 at pe.entry_point
}