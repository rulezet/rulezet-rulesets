import "pe"
rule _Diet_110__120_COM_
{
	meta:
		description = "Diet 1.10 - 1.20 [COM]"
	strings:
		$0 = {BE 00 00 BF 00 00 B9 00 00 3B FC 72 04 B4 4C CD 21 FD F3 A5 FC 8B F7 BF 00 01 AD AD 8B E8 B2 10 E9 00 00 64 6C 7A}
	condition:
		$0 at pe.entry_point
}