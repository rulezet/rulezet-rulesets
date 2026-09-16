import "pe"
rule _X3_
{
	meta:
		description = "X3"
	strings:
		$0 = {5E BF 00 01 57 B9 00 00 AC 34 00 AA E2 FA C3}
	condition:
		$0 at pe.entry_point
}