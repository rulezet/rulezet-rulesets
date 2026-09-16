import "pe"
rule _CrunchPE_v20xx_
{
	meta:
		description = "Crunch/PE v2.0.x.x"
	strings:
		$0 = {EB 10 55 E8 5D 81 ED 18 8B C5 55 60 9C 2B 85 89 85 FF}
	condition:
		$0 at pe.entry_point
}