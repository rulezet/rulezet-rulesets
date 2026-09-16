import "pe"
rule _XPack_131__166_COM_
{
	meta:
		description = "XPack 1.31 - 1.66 [COM]"
	strings:
		$0 = {8C C8 05 00 10 8E C0 BF 00 01 8B F7 FC B9 60 6D F3 A5 06 B8 77 01 50 CB 1E 06 1F 07 BE 00 02 BF 00 01 06 57 E8 11 00 33 C0 8B D8 8B C8 8B D0 8B F0 8B F8 8B E8 06 1F CB EB 1D 80 E2 0F 75 05 50 AD 8B E8 58 FE C2 03 ED C3 33 C9 E8 EC FF D1 D1}
	condition:
		$0 at pe.entry_point
}