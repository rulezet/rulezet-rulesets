import "pe"
rule _Limit_Archive_
{
	meta:
		description = "Limit Archive"
	strings:
		$0 = {4C 4D 1A}
	condition:
		$0 at pe.entry_point
}