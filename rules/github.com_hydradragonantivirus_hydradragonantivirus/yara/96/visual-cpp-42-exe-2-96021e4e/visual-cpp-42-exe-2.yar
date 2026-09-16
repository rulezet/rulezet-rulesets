import "pe"
rule _Visual_Cpp_42_EXE__2_
{
	meta:
		description = "Visual C++ 4.2 (EXE - 2)"
	strings:
		$0 = {64 A1 00 00 00 00 55 8B EC 6A FF 68 00 00 00 00 68 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 60 53 56 57 89 65 E8 FF 15 00 00 00 00 A3 00 00 00 00 33 C0 A0 00 00 00 00 A3 00 00 00 00 A1 00 00 00 00 C1 2D 00 00 00 00 10 25 FF 00 00 00 A3 00}
	condition:
		$0 at pe.entry_point
}