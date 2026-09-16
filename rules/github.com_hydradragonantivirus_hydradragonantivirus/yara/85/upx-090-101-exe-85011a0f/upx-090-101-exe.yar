import "pe"
rule _UPX_090__101_EXE_
{
	meta:
		description = "UPX 0.90 - 1.01 [EXE]"
	strings:
		$0 = {B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8C C8 05 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 12 10 73 E7 92 AF AD 0E 0E 0E 06 1F 07 16 BD 00 00 BB 00 80 55 CB 55 50 58 21 0B 03 03 07}
	condition:
		$0 at pe.entry_point
}