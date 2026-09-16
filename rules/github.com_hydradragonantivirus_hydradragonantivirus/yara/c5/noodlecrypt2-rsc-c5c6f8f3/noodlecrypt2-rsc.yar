import "pe"
rule _Noodlecrypt2__rsc_
{
	meta:
		description = "Noodlecrypt2 -> r!sc"
	strings:
		$0 = {EB 01 9A E8 76 00 00 00}
	condition:
		$0 at pe.entry_point
}