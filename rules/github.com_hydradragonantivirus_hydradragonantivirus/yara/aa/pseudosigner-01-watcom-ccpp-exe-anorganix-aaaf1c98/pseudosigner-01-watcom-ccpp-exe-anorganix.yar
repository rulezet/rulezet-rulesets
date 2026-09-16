import "pe"
rule _PseudoSigner_01_WATCOM_CCpp_EXE__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [WATCOM C/C++ EXE] --> Anorganix"
	strings:
		$0 = {E9 00 00 00 00 90 90 90 90 57 41 E9}
	condition:
		$0 at pe.entry_point
}