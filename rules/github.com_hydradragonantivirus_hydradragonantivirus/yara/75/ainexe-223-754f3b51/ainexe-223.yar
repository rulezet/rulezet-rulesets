import "pe"
rule _AinEXE_223_
{
	meta:
		description = "AinEXE 2.23"
	strings:
		$0 = {0E 07 B9 14 00 BE 00 01 33 FF FC F3 A4 A1 02 00 2D E1 0B 8E D0 BC 00 BE 8C D8 36 A3 00 BE 05 10 00 36 A3 02 BE 2E A1 0E 00 8A D4 B1 04 D2 EA D3 E0 8C D3 36 8B 2E 02 BE 2E 03 2E 0E 00 FD FE CA 78 17 81 ED 00 10 80 EF 10 8E DD 8E C3 BE FE FF}
	condition:
		$0 at pe.entry_point
}