import "pe"
rule _PseudoSigner_02_PE_Pack_099__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PE Pack 0.99] --> Anorganix"
	strings:
		$0 = {60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A}
	condition:
		$0 at pe.entry_point
}