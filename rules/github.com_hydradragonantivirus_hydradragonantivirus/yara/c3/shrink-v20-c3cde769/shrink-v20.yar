import "pe"
rule _Shrink_v20_
{
	meta:
		description = "Shrink v2.0"
	strings:
		$0 = {E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9}
	condition:
		$0 at pe.entry_point
}