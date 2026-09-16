import "pe"
rule _Vx_Caz1204_
{
	meta:
		description = "Vx: Caz.1204"
	strings:
		$0 = {E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10}
	condition:
		$0 at pe.entry_point
}