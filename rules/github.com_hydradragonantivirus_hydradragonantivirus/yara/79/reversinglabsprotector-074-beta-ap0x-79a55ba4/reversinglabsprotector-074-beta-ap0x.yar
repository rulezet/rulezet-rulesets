import "pe"
rule _ReversingLabsProtector_074_beta__Ap0x_
{
	meta:
		description = "ReversingLabsProtector 0.7.4 beta -> Ap0x"
	strings:
		$0 = {68 00 00 41 00 E8 01 00 00 00 C3 C3}
	condition:
		$0 at pe.entry_point
}