import "pe"
rule ASPackv2xxx : Alexey Solodovnikov
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$c0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 }
	condition:
		pe.imports ("kernel32.dll","GetProcAddress") and
		pe.imports ("kernel32.dll","GetModuleHandleA") and
		pe.imports ("kernel32.dll","LoadLibraryA") and
		$c0 at pe.entry_point
}