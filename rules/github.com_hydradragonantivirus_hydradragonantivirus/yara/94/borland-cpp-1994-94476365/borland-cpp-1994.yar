import "pe"
rule _Borland_Cpp_1994_
{
	meta:
		description = "Borland C++ 1994"
	strings:
		$0 = {8C CA 2E 89 ?? ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA A3 ?? ?? 8C}
	condition:
		$0 at pe.entry_point
}