import "pe"
rule _kkryptor_8__rsc_
{
	meta:
		description = "k.kryptor 8 -> r!sc"
	strings:
		$0 = {EB 6A 87 DB 00 00 00 00}
	condition:
		$0 at pe.entry_point
}