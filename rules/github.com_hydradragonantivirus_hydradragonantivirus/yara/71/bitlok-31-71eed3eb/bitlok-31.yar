import "pe"
rule _BITLOK_31_
{
	meta:
		description = "BITLOK 3.1"
	strings:
		$0 = {EB 06 B0 65 B4 4C CD 21 B4 30 CD 21 3C 03 72 F2 2E 8C 1E 00 00 8C DB 83 C3 10 2E 01 1E 3A 00 0E 1F EB 25 EA 83 F9 01 EB 0C EA 5F EB 03 EB F5 EA BE 61 00 EB 3D 74 56 EB 34 EA BF D2 00 EB 38 EA EB 3D 81 FE CF 00 EB 08 33 C0 EB EE EA EB F1 EA}
	condition:
		$0 at pe.entry_point
}