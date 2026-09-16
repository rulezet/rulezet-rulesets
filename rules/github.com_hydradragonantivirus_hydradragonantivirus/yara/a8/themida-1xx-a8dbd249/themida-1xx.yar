import "pe"
rule Themida_1xx : Oreans Technologies
{
	meta:
		author="_pusher_"
		date = "2016-06"
	strings:
				$a0 = { B8 00 00 00 00 60 0B C0 }
				$a1 = { 80 3B CC 0F 85 5F 00 00 00 }
				$a2 = { 80 38 E9 75 13 }
				$a5 = { 80 38 E9 75 03 }
		
				$a3 = { 8E C7 63 31 98 4C 26 93 C9 E4 F2 78 BC 5E 2F 17 }
				$a4 = { 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 }
	condition:
		($a0 in (pe.entry_point..pe.entry_point+0x50)
		and ($a1 or $a2 or $a5)
		and ($a3 or $a4))
}