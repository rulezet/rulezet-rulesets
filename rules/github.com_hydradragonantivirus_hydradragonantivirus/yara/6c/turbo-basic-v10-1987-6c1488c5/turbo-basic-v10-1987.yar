import "pe"
rule _Turbo_Basic_v10_1987_
{
	meta:
		description = "Turbo Basic v1.0 1987"
	strings:
		$0 = {2E 8C ?? ?? ?? 2E C7}
	condition:
		$0 at pe.entry_point
}