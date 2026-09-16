import "pe"
rule _Diet_145f_EXE_
{
	meta:
		description = "Diet 1.45f [EXE]"
	strings:
		$0 = {F9 9C EB 09 00 00 0A 00 00 00 55 F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA 00 00 03 D0 52 BA 00 00 52 BA 00 00 03 C2 8B D8 05 00 00 8E DB 8E C0 33 F6 33 FF B9 08 00 F3 A5 4B 48 4A 79 EE 8E C3 8E D8 BE 67 00 AD 8B E8 B2 10 CB 64 6C 7A}
	condition:
		$0 at pe.entry_point
}