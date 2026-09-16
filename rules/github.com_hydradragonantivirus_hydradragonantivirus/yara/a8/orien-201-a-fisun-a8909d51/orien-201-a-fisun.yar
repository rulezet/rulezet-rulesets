import "pe"
rule _ORiEN_201__A_Fisun_
{
	meta:
		description = "ORiEN 2.01 -> A. Fisun"
	strings:
		$0 = {E9 5D 01 00 00}
		$1 = {E9 5D 01 00 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}