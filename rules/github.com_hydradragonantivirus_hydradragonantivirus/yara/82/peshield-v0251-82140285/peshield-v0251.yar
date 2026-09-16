import "pe"
rule _PESHiELD_v0251_
{
	meta:
		description = "PESHiELD v0.251"
	strings:
		$0 = {B8 B9 83 F9 ?? 7E 06 80 30 40 E2 F5 E9}
	condition:
		$0 at pe.entry_point
}