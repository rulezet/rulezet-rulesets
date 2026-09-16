import "pe"
rule _PseudoSigner_02_ASProtect_
{
	meta:
		description = "PseudoSigner 0.2 [ASProtect"
	strings:
		$0 = {60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD}
	condition:
		$0 at pe.entry_point
}