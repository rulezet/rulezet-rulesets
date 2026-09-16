import "pe"
rule _Cygwin32__Cygwin_
{
	meta:
		description = "Cygwin32 -> Cygwin"
	strings:
		$0 = {55 89 E5 83 EC 04 83 3D}
	condition:
		$0 at pe.entry_point
}