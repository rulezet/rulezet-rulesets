import "pe"
rule _Nakedbind_10__nakedcrew_
{
	meta:
		description = "Nakedbind 1.0 -> nakedcrew"
	strings:
		$0 = {64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00}
	condition:
		$0 at pe.entry_point
}