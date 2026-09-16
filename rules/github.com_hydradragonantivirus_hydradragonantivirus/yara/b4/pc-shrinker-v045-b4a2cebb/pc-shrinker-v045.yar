import "pe"
rule _PC_Shrinker_v045_
{
	meta:
		description = "PC Shrinker v0.45"
	strings:
		$0 = {9C 60 BD 01 AD 54 3A 40 FF B5 50 3A 40 6A 40 FF 95 88 3A 40 50 50 2D 89}
	condition:
		$0 at pe.entry_point
}