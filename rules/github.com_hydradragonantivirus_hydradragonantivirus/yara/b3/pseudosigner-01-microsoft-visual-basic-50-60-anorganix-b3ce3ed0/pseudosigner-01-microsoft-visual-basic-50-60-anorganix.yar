import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Basic_50__60__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual Basic 5.0 - 6.0] --> Anorganix"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9}
	condition:
		$0 at pe.entry_point
}