import "pe"
rule _FSG_v110_Eng__dulekxt__MASM32_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32)"
	strings:
		$0 = {EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A}
	condition:
		$0 at pe.entry_point
}