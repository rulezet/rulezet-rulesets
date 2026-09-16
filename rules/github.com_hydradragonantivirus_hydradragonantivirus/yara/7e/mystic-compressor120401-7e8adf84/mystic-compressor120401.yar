import "pe"
rule Mystic_Compressor120401
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 47 44 49 33 32 2E 64 6C 6C 00 00 00 70 75 73 68 20 69 6D 6D }
		$a1 = { 44 65 6C 70 68 69 41 70 70 6C 69 63 61 74 69 6F 6E }
	condition:
		pe.imports ("kernel32.dll","GlobalAlloc") and
		pe.imports ("kernel32.dll","GetModuleHandleA") and
		pe.imports ("kernel32.dll","GetModuleHandleW") and
		$a0 and $a1
}