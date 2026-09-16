import "pe"
rule _Turbo_C_or_Borland_Cpp_
{
	meta:
		description = "Turbo C or Borland C++"
	strings:
		$0 = {BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA}
	condition:
		$0 at pe.entry_point
}