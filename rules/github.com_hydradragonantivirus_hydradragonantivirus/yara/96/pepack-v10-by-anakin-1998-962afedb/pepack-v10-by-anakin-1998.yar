import "pe"
rule _PEPACK_v10_by_ANAKiN_1998__
{
	meta:
		description = "PE-PACK v1.0 by ANAKiN 1998 (???)"
	strings:
		$0 = {74 ?? E9 ?? ?? ?? ?? 00 00 00 00}
	condition:
		$0 at pe.entry_point
}