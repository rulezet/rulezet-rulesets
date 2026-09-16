import "pe"
rule _DEF_v10_
{
	meta:
		description = "DEF v1.0"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 23 35}
	condition:
		$0 at pe.entry_point
}