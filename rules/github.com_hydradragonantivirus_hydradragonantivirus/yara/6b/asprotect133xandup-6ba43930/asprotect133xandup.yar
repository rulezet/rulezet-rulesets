import "pe"
rule ASProtect133xAndUp : Alexey Solodovnikov
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$c0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }
	condition:
		pe.imports ("kernel32.dll","GetProcAddress") and
		pe.imports ("kernel32.dll","GetModuleHandleA") and
		pe.imports ("kernel32.dll","LoadLibraryA") and
		pe.imports ("kernel32.dll","RaiseException") and
		$c0 at pe.entry_point
}