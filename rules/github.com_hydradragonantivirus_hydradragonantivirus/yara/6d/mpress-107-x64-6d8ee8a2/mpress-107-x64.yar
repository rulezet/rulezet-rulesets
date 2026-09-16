import "pe"
rule mpress_107_x64 : Matcode
{
	meta:
		author="_pusher_"
		date = "2016-09"
	strings:
		$a0 = { 57 56 53 51 52 41 50 48 8D 05 6F 03 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31 }
		$a1 = { 4D 5A 40 00 01 00 00 00 02 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 57 69 6E 36 34 20 2E 45 58 45 2E 0D 0A 24 40 00 00 00 }
	condition:
		$a0 at pe.entry_point and $a1 at 0
}