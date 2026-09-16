import "pe"
rule _PseudoSigner_01__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90}
	condition:
		$0 at pe.entry_point
}