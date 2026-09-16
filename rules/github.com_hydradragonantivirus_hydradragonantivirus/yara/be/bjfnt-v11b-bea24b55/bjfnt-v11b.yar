import "pe"
rule _BJFnt_v11b_
{
	meta:
		description = ".BJFnt v1.1b"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB}
	condition:
		$0 at pe.entry_point
}