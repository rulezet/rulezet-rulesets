import "pe"
rule _kkryptor_5__rsc_
{
	meta:
		description = "k.kryptor 5 -> r!sc"
	strings:
		$0 = {E8 03 00 00 00 E9 EB 6C 58 40 FF E0}
	condition:
		$0 at pe.entry_point
}