import "pe"
rule Mystic_Compressor120428
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 63 6D 63 66 67 33 32 2E 64 6C 6C 00 }
		$a1 = { 44 65 6C 70 68 69 41 70 70 6C 69 63 61 74 69 6F 6E }
	condition:
		pe.imports ("kernel32.dll","GetStartupInfoW") and
		pe.imports ("kernel32.dll","LocalAlloc") and
		pe.imports ("kernel32.dll","GetTickCount") and
		$a0 and $a1
}