import "pe"
rule _ExeTools_v21_Encruptor_by_DISMEMBER_
{
	meta:
		description = "ExeTools v2.1 Encruptor by DISMEMBER"
	strings:
		$0 = {E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74}
	condition:
		$0 at pe.entry_point
}