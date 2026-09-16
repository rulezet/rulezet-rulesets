import "pe"
rule _CrunchPE_
{
	meta:
		description = "Crunch/PE"
	strings:
		$0 = {55 E8 5D 83 ED 06 8B C5 55 60 89 AD 2B 85 89 85 80 BD 75 09 C6}
	condition:
		$0 at pe.entry_point
}