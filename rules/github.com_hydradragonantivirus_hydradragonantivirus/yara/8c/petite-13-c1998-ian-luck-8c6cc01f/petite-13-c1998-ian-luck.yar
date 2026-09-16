import "pe"
rule _Petite_13__c1998_Ian_Luck_
{
	meta:
		description = "Petite 1.3 -> (c)1998 Ian Luck"
	strings:
		$0 = {9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03}
	condition:
		$0 at pe.entry_point
}