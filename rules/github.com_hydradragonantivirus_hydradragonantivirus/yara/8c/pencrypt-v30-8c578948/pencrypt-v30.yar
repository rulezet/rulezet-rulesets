import "pe"
rule _PEncrypt_v30_
{
	meta:
		description = "PEncrypt v3.0"
	strings:
		$0 = {E9 ?? F0 0F}
	condition:
		$0 at pe.entry_point
}