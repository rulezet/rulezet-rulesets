import "pe"
rule _LCCWin32_1x_
{
	meta:
		description = "LCC-Win32 1.x"
	strings:
		$0 = {64 A1 00 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? 00 68 9A 10 40 00 50}
	condition:
		$0 at pe.entry_point
}