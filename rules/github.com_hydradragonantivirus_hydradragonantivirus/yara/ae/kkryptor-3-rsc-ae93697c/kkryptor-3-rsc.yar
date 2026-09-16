import "pe"
rule _kkryptor_3__rsc_
{
	meta:
		description = "k.kryptor 3 -> r!sc"
	strings:
		$0 = {EB 66 87 DB 00 00 00 00}
	condition:
		$0 at pe.entry_point
}