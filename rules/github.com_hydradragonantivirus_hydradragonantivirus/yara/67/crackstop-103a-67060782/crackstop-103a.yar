import "pe"
rule _Crackstop_103a_
{
	meta:
		description = "Crackstop 1.03a"
	strings:
		$0 = {B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC 03 46 FA 05 05 00 FF E0 9A 53 45 EB 05 B8 08 00 EB EE B8 06 00 29 46 FA EB 02 8E F8 2B E0 CF EA 11 0E 1F E8 02 00 24 24 5A B4 09 CD 21 FA 33 C0 89 46 FA B8 D2 04 40 2B D8 8B 46 FA 0B C0 75 B2 FB B0}
	condition:
		$0 at pe.entry_point
}