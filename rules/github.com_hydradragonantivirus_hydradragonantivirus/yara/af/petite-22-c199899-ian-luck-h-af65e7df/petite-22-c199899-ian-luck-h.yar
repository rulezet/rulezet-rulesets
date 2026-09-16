import "pe"
rule _Petite_22__c199899_Ian_Luck_h_
{
	meta:
		description = "Petite 2.2 -> (c)1998-99 Ian Luck (h)"
	strings:
		$0 = {66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42}
	condition:
		$0 at pe.entry_point
}