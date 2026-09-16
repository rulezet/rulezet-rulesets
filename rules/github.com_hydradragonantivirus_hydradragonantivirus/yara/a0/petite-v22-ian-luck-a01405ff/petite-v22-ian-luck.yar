import "pe"
rule _PEtite_v22__Ian_Luck_
{
	meta:
		description = "PEtite v2.2 -> Ian Luck"
	strings:
		$0 = {B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50}
	condition:
		$0 at pe.entry_point
}