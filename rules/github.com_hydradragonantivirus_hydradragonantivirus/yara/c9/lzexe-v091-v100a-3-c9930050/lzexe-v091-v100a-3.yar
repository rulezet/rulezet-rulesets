import "pe"
rule _LZEXE_v091_v100a_3_
{
	meta:
		description = "LZEXE v0.91, v1.00a (3)"
	strings:
		$0 = {50 06 0E 1F 8B 0E}
	condition:
		$0 at pe.entry_point
}