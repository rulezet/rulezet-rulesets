import "pe"
rule Mystic_Compressor_xxxx
{
		meta:
		author="_pusher_"
		date = "2015-12"
	strings:
		$a0 = { 63 6D 63 66 67 33 32 2E 64 6C 6C 00 }
		$a1 = { 22 58 2D 54 65 72 6D 34 22 }
	condition:
		pe.imports ("kernel32.dll","GetStartupInfoA") and
		pe.imports ("kernel32.dll","VirtualAlloc") and
		pe.imports ("kernel32.dll","LoadLibraryA") and
		$a0 and $a1
}