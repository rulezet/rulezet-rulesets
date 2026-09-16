import "pe"
rule _ProPack_214_m1_EXE_
{
	meta:
		description = "ProPack 2.14 -m1 [EXE]"
	strings:
		$0 = {0E 8C D3 8E C3 8C CA 8E DA 8B 0E 08 00 8B F1 83 EE 02 8B FE D1 E9 FD F3 A5 53 B8 35 00 50 8B 2E 0A 00 03 16 0C 00 CB B8 00 10 3B C5 76 02 8B C5 2B E8 2B D8 2B D0 8E DA 8E C3 B1 03 D3 E0 8B C8 D1 E0 48 48 8B F0 8B F8 F3 A5 0B ED 75 D9 FC 07}
	condition:
		$0 at pe.entry_point
}