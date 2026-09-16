import "pe"
rule _HackStop_098_EXE_
{
	meta:
		description = "HackStop 0.98 [EXE]"
	strings:
		$0 = {B4 30 CD 21 86 E0 3D 00 03 73 06 B0 FF B4 4C CD 21 50 B8 EB 04 58 EB FB 9A B8 00 33 CD 21 50 E8 E4 03 8D B2 00 B8 01 33 CD 21 50 B8 EB 06 58 EB FB 66 B1 12 E8 CF 03 8D EB 02 43 93 50 55 52 8C D2 FA 50 B8 EB 04 58 EB FB 9A 8C C8 8E D0 EB 02}
	condition:
		$0 at pe.entry_point
}