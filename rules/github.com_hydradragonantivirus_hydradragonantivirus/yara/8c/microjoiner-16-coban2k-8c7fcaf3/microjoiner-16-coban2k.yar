import "pe"
rule _MicroJoiner_16__coban2k_
{
	meta:
		description = "MicroJoiner 1.6 -> coban2k"
	strings:
		$0 = {33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B}
	condition:
		$0 at pe.entry_point
}