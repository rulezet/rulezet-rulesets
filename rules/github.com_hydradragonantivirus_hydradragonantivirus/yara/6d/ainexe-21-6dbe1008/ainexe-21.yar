import "pe"
rule _AinEXE_21_
{
	meta:
		description = "AinEXE 2.1"
	strings:
		$0 = {A1 02 00 2D E1 0B 8E D0 BC 00 BE 8C D8 36 A3 00 BE 05 10 00 36 A3 02 BE 2E A1 0E 00 8A D4 B1 04 D2 EA FE C9 D3 E0 8C D3 36 8B 2E 02 BE 2E 03 2E 0E 00 FD 81 ED 00 10 80 EF 10 8E DD 8E C3 BE FE FF 8B FE FE CA 78 07 B9 00 80 F3 A5 EB E5 8B C8}
	condition:
		$0 at pe.entry_point
}