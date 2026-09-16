import "pe"
rule _Splasher_v10__v30_
{
	meta:
		description = "Splasher v1.0 - v3.0"
	strings:
		$0 = {9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84}
	condition:
		$0 at pe.entry_point
}