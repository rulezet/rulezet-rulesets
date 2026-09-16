import "pe"
rule _Vx_Noon1163_
{
	meta:
		description = "Vx: Noon.1163"
	strings:
		$0 = {E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC}
	condition:
		$0 at pe.entry_point
}