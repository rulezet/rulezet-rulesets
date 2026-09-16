import "pe"
rule _PseudoSigner_01_Yodas_Protector_102_
{
	meta:
		description = "PseudoSigner 0.1 [Yoda's Protector 1.02"
	strings:
		$0 = {E8 03 00 00 00 EB 01 90 90 E9}
		$1 = {E8 03 00 00 00 EB 01 90 90 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}