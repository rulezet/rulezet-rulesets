import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Cpp_70_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 7.0 DLL] --> Anorganix"
	strings:
		$0 = {55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9}
	condition:
		$0 at pe.entry_point
}