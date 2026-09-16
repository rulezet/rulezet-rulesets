import "pe"
rule _SQZ_Archive_
{
	meta:
		description = "SQZ Archive"
	strings:
		$0 = {48 4C 53 51 5A}
	condition:
		$0 at pe.entry_point
}