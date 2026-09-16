import "pe"
rule _PEtite_v22_
{
	meta:
		description = "PEtite v2.2"
	strings:
		$0 = {B8 66 9C 60}
	condition:
		$0 at pe.entry_point
}