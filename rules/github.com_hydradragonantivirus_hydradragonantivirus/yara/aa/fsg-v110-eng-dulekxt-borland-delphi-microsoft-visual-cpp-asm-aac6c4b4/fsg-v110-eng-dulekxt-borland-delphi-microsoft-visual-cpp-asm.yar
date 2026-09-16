import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cpp__ASM_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++ / ASM)"
	strings:
		$0 = {EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4}
	condition:
		$0 at pe.entry_point
}