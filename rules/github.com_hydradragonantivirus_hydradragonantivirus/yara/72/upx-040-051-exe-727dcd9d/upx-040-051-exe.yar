import "pe"
rule _UPX_040__051_EXE_
{
	meta:
		description = "UPX 0.40 - 0.51 [EXE]"
	strings:
		$0 = {8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 00 00 00 00 00 0E 0E 00 00 00 00 00 00 00 00 00 00 00 00 55 50 58 21 05 00 02 07}
	condition:
		$0 at pe.entry_point
}