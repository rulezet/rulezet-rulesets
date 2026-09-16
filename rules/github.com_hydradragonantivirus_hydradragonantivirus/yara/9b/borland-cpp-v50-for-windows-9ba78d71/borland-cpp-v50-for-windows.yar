import "pe"
rule _Borland_Cpp_v50_for_Windows_
{
	meta:
		description = "Borland C++ v5.0 for Windows"
	strings:
		$0 = {EB ?? 53 51 06 33 C0 50 9A ?? ?? ?? ?? 58 07 59 5B 9A}
	condition:
		$0 at pe.entry_point
}