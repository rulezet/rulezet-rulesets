import "pe"
rule _PKLite_201_COM_
{
	meta:
		description = "PKLite 2.01 [COM]"
	strings:
		$0 = {50 B8 00 00 BA 00 00 3B C4 73 79 8B C4 2D 42 03 25 F0 FF 8B F8 B9 A1 00 BE 8E 01 FC F3 A5 8B D8 B1 04 D3 EB 8C D9 03 D9 53 33 DB 53 CB 90 01 02 50 4B 4C 49 54 45 20 43 6F 70 72 2E 20 31 39 39 30 2D 31 39 39 35 20}
	condition:
		$0 at pe.entry_point
}