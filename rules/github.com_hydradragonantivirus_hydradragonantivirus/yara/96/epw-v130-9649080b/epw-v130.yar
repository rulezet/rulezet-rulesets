import "pe"
rule _EPW_v130_
{
	meta:
		description = "EPW v1.30"
	strings:
		$0 = {06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E}
	condition:
		$0 at pe.entry_point
}