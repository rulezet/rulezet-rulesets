import "pe"
rule _PECompact_v094_
{
	meta:
		description = "PECompact v0.94"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7}
	condition:
		$0 at pe.entry_point
}