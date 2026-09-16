import "pe"
rule Mystic_Compressor120507
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 63 6D 63 66 67 33 32 2E 64 6C 6C 00 }
		$a1 = { 44 65 6C 70 68 69 41 70 70 6C 69 63 61 74 69 6F 6E }
	condition:
		pe.imports ("kernel32.dll","GetCurrentThread") and
		pe.imports ("kernel32.dll","VirtualAlloc") and
		pe.imports ("kernel32.dll","LoadLibraryA") and
		$a0 and $a1
}