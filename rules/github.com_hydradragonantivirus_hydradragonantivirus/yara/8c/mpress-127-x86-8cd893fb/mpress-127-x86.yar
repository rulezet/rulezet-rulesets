import "pe"
rule mpress_127_x86 : Matcode
{
	meta:
		author="_pusher_"
		date = "2015-11"	
	strings:
		$a0 = { 60 E8 00 00 00 00 58 05 9E 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 }
		$a1 = { 4D 5A 40 00 01 00 00 00 02 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 57 69 6E 33 32 20 2E 45 58 45 2E 0D 0A 24 40 00 00 00 }
	condition:
		$a0 at pe.entry_point and $a1 at 0
}