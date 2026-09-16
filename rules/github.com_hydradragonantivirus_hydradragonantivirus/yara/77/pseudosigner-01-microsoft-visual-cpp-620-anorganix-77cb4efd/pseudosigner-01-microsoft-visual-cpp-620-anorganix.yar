import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Cpp_620__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual C++ 6.20] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B}
	condition:
		$0 at pe.entry_point
}