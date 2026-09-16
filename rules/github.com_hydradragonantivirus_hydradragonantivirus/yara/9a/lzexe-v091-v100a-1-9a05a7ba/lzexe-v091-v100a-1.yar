import "pe"
rule _LZEXE_v091_v100a_1_
{
	meta:
		description = "LZEXE v0.91, v1.00a (1)"
	strings:
		$0 = {06 0E 1F 8B ?? ?? ?? 8B F1 4E 89 F7}
	condition:
		$0 at pe.entry_point
}