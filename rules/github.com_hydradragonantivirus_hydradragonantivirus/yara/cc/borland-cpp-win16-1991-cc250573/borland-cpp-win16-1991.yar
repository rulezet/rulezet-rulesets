import "pe"
rule _Borland_Cpp_Win16_1991_
{
	meta:
		description = "Borland C++ Win16 (1991)"
	strings:
		$0 = {9A FF FF 00 00 0B C0 75 03 E9 D5 00 8C 06 16 00 89 1E 1C 00 89 36 1A 00 89 3E 18 00 89 16 1E 00 B8 FF FF 50 9A FF FF 00 00 33 C0 1E 07 BF DE 03 B9 7E 0A 2B CF FC F3 AA 33 C0 50 9A FF FF 00 00 FF 36 18 00 9A FF FF 00 00 0B C0 75 03 E9 91 00}
	condition:
		$0 at pe.entry_point
}