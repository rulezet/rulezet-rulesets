import "pe"
rule _FSG_v110_Eng__dulekxt__MASM32__TASM32__Microsoft_Visual_Basic_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32 / Microsoft Visual Basic)"
	strings:
		$0 = {F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94}
	condition:
		$0 at pe.entry_point
}