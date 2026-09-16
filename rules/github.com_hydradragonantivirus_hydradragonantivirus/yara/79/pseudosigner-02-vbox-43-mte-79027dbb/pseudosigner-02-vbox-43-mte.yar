import "pe"
rule _PseudoSigner_02_VBOX_43_MTE_
{
	meta:
		description = "PseudoSigner 0.2 [VBOX 4.3 MTE"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0}
	condition:
		$0 at pe.entry_point
}