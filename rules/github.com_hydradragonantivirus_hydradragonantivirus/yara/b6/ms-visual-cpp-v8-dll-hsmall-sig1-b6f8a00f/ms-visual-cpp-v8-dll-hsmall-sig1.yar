import "pe"
rule _MS_Visual_Cpp_v8_DLL_hsmall_sig1_
{
	meta:
		description = "MS Visual C++ v.8 DLL (h-small sig1)"
	strings:
		$0 = {8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC}
	condition:
		$0 at pe.entry_point
}