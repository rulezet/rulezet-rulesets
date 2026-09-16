import "pe"
rule _FSG_v133_
{
	meta:
		description = "FSG v1.33"
	strings:
		$0 = {89 25 A8 11 40 ?? BF ?? 31 C0 B9 ?? 29 F9 FC F3}
	condition:
		$0 at pe.entry_point
}