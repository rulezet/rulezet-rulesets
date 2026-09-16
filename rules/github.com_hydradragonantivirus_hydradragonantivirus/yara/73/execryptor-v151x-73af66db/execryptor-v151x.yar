import "pe"
rule _EXECryptor_v151x_
{
	meta:
		description = "EXECryptor v1.5.1.x"
	strings:
		$0 = {E8 24 8B 4C 24 0C C7 01 17 01 C7 81 B8 31 C0 89}
	condition:
		$0 at pe.entry_point
}