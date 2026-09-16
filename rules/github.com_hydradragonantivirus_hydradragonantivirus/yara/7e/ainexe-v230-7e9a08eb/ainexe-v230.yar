import "pe"
rule _AINEXE_v230_
{
	meta:
		description = "AINEXE v2.30"
	strings:
		$0 = {0E 07 B9 ?? ?? BE ?? ?? 33 FF FC F3 A4 A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8}
	condition:
		$0 at pe.entry_point
}