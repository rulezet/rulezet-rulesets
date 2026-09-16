import "pe"
rule _PseudoSigner_02_VOB_ProtectCD_5_
{
	meta:
		description = "PseudoSigner 0.2 [VOB ProtectCD 5"
	strings:
		$0 = {36 3E 26 8A C0 60 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}