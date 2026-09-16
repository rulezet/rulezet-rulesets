import "pe"
rule _Rec_038_
{
	meta:
		description = "Rec 0.38"
	strings:
		$0 = {06 1E B4 30 CD 21 3C 02 73 05 33 C0 06 50 CB BF 66 23 8B 36 02 00 2B F7 81 FE 00 10 EB 0A B4 4A CD 21 BF 77 13 B9 81 17 00 00 EB 04 00 EB FB 9A EB}
	condition:
		$0 at pe.entry_point
}