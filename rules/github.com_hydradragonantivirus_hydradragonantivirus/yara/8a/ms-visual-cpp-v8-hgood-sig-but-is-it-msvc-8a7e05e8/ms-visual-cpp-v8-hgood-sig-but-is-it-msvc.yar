import "pe"
rule _MS_Visual_Cpp_v8_hgood_sig_but_is_it_MSVC_
{
	meta:
		description = "MS Visual C++ v.8 (h-good sig, but is it MSVC?)"
	strings:
		$0 = {E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00}
	condition:
		$0 at pe.entry_point
}