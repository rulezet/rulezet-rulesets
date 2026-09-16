import "pe"
rule _PC_Shrinker_v020_
{
	meta:
		description = "PC Shrinker v0.20"
	strings:
		$0 = {BD 01 AD 55 39 40 8D B5 35 39}
	condition:
		$0 at pe.entry_point
}