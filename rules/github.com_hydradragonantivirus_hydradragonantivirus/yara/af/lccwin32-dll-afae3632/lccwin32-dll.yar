import "pe"
rule _LCCWin32_DLL_
{
	meta:
		description = "LCC-Win32 DLL"
	strings:
		$0 = {55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 00 00 00 FF 75 10 FF 75 0C FF 75 08 A1}
	condition:
		$0 at pe.entry_point
}