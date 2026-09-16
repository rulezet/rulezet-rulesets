import "pe"
rule _PECompact_v090__v092_
{
	meta:
		description = "PECompact v0.90 - v0.92"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 5D 55 58 81 ED 2B 85 01 85 50 B9}
	condition:
		$0 at pe.entry_point
}