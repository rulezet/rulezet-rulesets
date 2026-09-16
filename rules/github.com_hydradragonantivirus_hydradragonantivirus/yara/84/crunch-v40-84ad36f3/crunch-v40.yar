import "pe"
rule _Crunch_v40_
{
	meta:
		description = "Crunch v4.0"
	strings:
		$0 = {E8 58 83 E8 05 50 5F 57 8B F7 81 EF 83 C6 39 BA 8B DF B9 0B 8B}
	condition:
		$0 at pe.entry_point
}