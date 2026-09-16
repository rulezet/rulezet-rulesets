import "pe"
rule _PECompact_v168__v184_
{
	meta:
		description = "PECompact v1.68 - v1.84"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC}
	condition:
		$0 at pe.entry_point
}