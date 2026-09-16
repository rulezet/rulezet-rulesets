rule msvc71_dll
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.1 DLL"
		group = "444"
		function = "0"
	strings:
		$a0 = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 }
	condition:
		$a0
}