import "pe"
rule _MegaLite_120_
{
	meta:
		description = "MegaLite 1.20"
	strings:
		$0 = {B8 00 00 BA 00 00 05 00 00 3B 2D 73 67 72 1B B4 09 BA 18 01 CD 21 CD 90 4E 6F 74 20 65 6E 6F 75 67 68 20 6D 65 6D 6F 72 79 24 2D 20 00 8E D0 2D 00 00 8E C0 50 B9 00 00 33 FF 56 BE 42 01 FC F2 A5 CA FD 8C DB 53 83 C3 00 03 DA 8C CD 8B C2 80}
	condition:
		$0 at pe.entry_point
}