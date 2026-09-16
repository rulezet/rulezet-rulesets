import "pe"
rule _Borland_Delphi_3_1_
{
	meta:
		description = "Borland Delphi 3 (1)"
	strings:
		$0 = {55 8B EC 83 C4 F4 53 56 A1 0C CF 42 00 C6 00 01 B8 00 25 42 00 E8 00 00 FE FF BE 1C E1 42 00 A1 90 CE 42 00 E8 00 00 FE FF A1 CC CE 42 00 BA 00 00 42 00 E8 00 FD FE FF 84 C0 75 05 E8 00 02 FF FF E8 00 07 FF FF 33 C0 A3 14 E1 42 00 33 C0 A3}
	condition:
		$0 at pe.entry_point
}