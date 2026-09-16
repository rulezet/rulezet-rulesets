import "pe"
rule _Upack_Patch__Sign_by_hot_UNP_
{
	meta:
		description = "Upack_Patch -> Sign by hot_UNP"
	strings:
		$0 = {81 3A 00 00 00 02 00 00 00 00}
		$1 = {2A A3 F2 54 CE}
	condition:
		$0 at pe.entry_point or $1
}