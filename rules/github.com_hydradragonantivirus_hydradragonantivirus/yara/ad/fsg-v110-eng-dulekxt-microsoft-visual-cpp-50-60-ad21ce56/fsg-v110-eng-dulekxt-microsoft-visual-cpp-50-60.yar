import "pe"
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_50__60_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 5.0 / 6.0)"
	strings:
		$0 = {33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB}
	condition:
		$0 at pe.entry_point
}