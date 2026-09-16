import "pe"
rule _Rec_032_
{
	meta:
		description = "Rec 0.32"
	strings:
		$0 = {06 1E 52 B8 02 30 1E CD 21 86 E0 3D FE 02 73 02 CD 20 0E 1F B4 09 E8 03 00 24 24 EA 5A CD 21 EB 02 D8 88 1F 5A B4 30 CD 21 3C 03 73 02 CD 20 3C 03 73 02 33 C0 BF 01 02 8B 03 90 2B F7 90 BF 06 07 B9 01 02 53 BB EB 04 5B EB FB 9A EB 2D FE 20}
	condition:
		$0 at pe.entry_point
}