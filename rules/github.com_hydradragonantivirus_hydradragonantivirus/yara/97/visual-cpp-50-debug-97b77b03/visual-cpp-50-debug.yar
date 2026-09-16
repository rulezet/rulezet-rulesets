import "pe"
rule _Visual_Cpp_50_debug_
{
	meta:
		description = "Visual C++ 5.0 (debug)"
	strings:
		$0 = {55 8B EC 6A FF 68 00 00 42 00 68 00 00 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 F0 53 56 57 89 65 E8 FF 15 00 C1 42 00 A3 00 A1 42 00 A1 00 A1 42 00 C1 E8 08 25 FF 00 00 00 A3 00 A1 42 00 8B 0D 00 A1 42 00 81 E1 FF 00 00 00 89}
	condition:
		$0 at pe.entry_point
}