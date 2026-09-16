import "pe"
rule _PC_Guard_150_for_Win16_
{
	meta:
		description = "PC Guard 1.50 for Win16"
	strings:
		$0 = {50 53 51 52 56 57 55 1E 06 06 33 C0 50 2E FF 1E 01 0F 0B C0 74 F4 50 8C CB 53 50 2E FF 1E 09 0F 0B C0 75 03 58 EB EF 8E D8 58 07 A3 ED 0E 89 3E EB 0E 8C 06 EF 0E B8 D7 8A BF EA 0E 2D 62 8A 8B D0 B9 75 0E 96 FD F6 C1 1F 75 02 8B F2 AC BB 88}
	condition:
		$0 at pe.entry_point
}