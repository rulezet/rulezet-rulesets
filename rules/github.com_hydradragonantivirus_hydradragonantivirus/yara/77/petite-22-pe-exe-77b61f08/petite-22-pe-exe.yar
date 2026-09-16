import "pe"
rule _Petite_22_PE_EXE_
{
	meta:
		description = "Petite 2.2 [PE EXE]"
	strings:
		$0 = {B8 00 00 00 00 6A 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 70 BC 00 00 6A 00 FF 50 1C 8B CC 8D A0 70 BC 00 00 89 61 2E 68 00 00 00 00 51 8B 7C 24 04 8B 33 66 81 C7 80 07 8D 74 1E 08 89 3B 53 8B}
	condition:
		$0 at pe.entry_point
}