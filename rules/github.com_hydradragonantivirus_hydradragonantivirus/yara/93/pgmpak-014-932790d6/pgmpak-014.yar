import "pe"
rule _PGMPAK_014_
{
	meta:
		description = "PGMPAK 0.14"
	strings:
		$0 = {1E 17 50 B4 30 CD 21 3C 02 73 04 B4 4C CD 21 FC BE 9A 03 BF 00 09 E8 1F FF E8 1C FF BB 3F 00 00 FF 00 8A C3 8B F3 8B B0 00 0A 8A 8F C0 09 BF 01 00 D3 E7 74 06 BD 00 07 E8 B8 FF 04 02 8B F3 8B B0 40 09 8A 8F 00 09 80 F9 09 73 08 BD 00 01 E8}
	condition:
		$0 at pe.entry_point
}