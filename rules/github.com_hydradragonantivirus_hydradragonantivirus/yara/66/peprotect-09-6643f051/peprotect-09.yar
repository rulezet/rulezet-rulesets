import "pe"
rule _PEPROTECT_09_
{
	meta:
		description = "PE-PROTECT 0.9"
	strings:
		$0 = {E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at pe.entry_point
}