import "pe"
rule _LZEXE_090_
{
	meta:
		description = "LZEXE 0.90"
	strings:
		$0 = {06 0E 1F 8B 0E 0C 00 8B F1 4E 89 F7 8C DB 03 1E 0A 00 8E C3 B4 00 31 ED FD AC 01 C5 AA E2 FA 8B 16 0E 00 8A C2 29 C5 8A C6 29 C5 39 D5 74 0C BA 91 01 B4 09 CD 21 B8 FF 4C CD 21 53 B8 53 00 50 CB 2E 8B 2E 08 00 8C DA 89 E8 3D 00 10 76 03 B8}
	condition:
		$0 at pe.entry_point
}