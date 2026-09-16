import "pe"
rule _Stones_PE_Encruptor_v113_
{
	meta:
		description = "Stone`s PE Encruptor v1.13"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81}
	condition:
		$0 at pe.entry_point
}