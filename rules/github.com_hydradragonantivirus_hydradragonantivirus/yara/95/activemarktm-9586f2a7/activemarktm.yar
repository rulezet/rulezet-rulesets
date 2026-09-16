import "pe"
rule _ActiveMARKTM_
{
	meta:
		description = "ActiveMARK[TM"
	strings:
		$0 = {79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF}
		$1 = {79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}