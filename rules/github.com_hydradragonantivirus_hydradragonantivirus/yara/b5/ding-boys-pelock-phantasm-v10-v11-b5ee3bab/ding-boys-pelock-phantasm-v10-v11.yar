import "pe"
rule _Ding_Boys_PElock_Phantasm_v10__v11_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v1.0 / v1.1"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ??}
	condition:
		$0 at pe.entry_point
}