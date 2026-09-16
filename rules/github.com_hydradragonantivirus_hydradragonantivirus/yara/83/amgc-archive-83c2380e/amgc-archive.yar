import "pe"
rule _AMGC_Archive_
{
	meta:
		description = "AMGC Archive"
	strings:
		$0 = {AD 36 22 00}
	condition:
		$0 at pe.entry_point
}