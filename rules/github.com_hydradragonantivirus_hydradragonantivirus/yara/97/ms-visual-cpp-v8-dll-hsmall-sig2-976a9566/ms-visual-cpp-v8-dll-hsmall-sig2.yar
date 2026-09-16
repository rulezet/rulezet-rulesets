import "pe"
rule _MS_Visual_Cpp_v8_DLL_hsmall_sig2_
{
	meta:
		description = "MS Visual C++ v.8 DLL (h-small sig2)"
	strings:
		$0 = {8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01}
	condition:
		$0 at pe.entry_point
}