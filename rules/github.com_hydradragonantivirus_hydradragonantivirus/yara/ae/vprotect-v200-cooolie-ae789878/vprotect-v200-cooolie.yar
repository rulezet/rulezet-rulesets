import "pe"
rule _Vprotect_V200__CoooLie_
{
	meta:
		description = "Vprotect V2.0.0 -> CoooLie"
	strings:
		$0 = {57 5F 8D BF FA FF FF FF 55 66 8B C0 5D 8D BF 06 00 00 00 8A D2 8B C9 66 50 8D AD FD FF FF FF 8D AD 03 00 00 00 66 58 87 DF 66 F7 D2 55 8A C9 5D 66 F7 D2 87 DF 8B 67 28 50 66 8B C0 58 61 F6 D5 53 5B F6 D5 66 87 C6 51 59 66 87 C6 F7 D6 66 52 66 5A F7 D6 9D 8D B6 E5 FF FF FF 66 51 F6 D2 8B D2 F6 D2 66 59 8D B6 1B 00 00 00 66 51 66 59}
	condition:
		$0 at pe.entry_point
}