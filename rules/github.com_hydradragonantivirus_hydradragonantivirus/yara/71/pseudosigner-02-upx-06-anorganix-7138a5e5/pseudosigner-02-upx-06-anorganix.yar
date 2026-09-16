import "pe"
rule _PseudoSigner_02_UPX_06__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [UPX 0.6] --> Anorganix"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00}
	condition:
		$0 at pe.entry_point
}