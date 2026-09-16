import "pe"
rule _Borland_Cpp_1991_
{
	meta:
		description = "Borland C++ 1991"
	strings:
		$0 = {2E 8C 06 ?? ?? 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F}
	condition:
		$0 at pe.entry_point
}