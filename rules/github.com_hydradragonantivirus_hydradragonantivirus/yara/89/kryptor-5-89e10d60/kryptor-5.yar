import "pe"
rule _kryptor_5_
{
	meta:
		description = "kryptor 5"
	strings:
		$0 = {E8 03 E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75}
	condition:
		$0 at pe.entry_point
}