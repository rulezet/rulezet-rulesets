import "pe"
rule ms_vc6_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0 DLL"
		group = "15"
		function = "17"
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }
	condition:
		$a0 at pe.entry_point
}