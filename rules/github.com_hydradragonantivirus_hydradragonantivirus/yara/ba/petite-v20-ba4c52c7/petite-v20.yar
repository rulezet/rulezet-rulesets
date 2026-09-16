import "pe"
rule _PEtite_v20_
{
	meta:
		description = "PEtite v2.0"
	strings:
		$0 = {B8 6A 68 64 FF 35 64 89 25 66 9C 60}
	condition:
		$0 at pe.entry_point
}