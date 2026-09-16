import "pe"
rule Themida_2xx : Oreans Technologies
{
	meta:
		author="_pusher_"
		date = "2016-08"
	strings:
		$a0 = { E8 01 00 00 00 CC }
		$a1 = { 80 3B CC 0F 85 5F 00 00 00 }
		$a2 = { 80 3B CC 75 19 }
		
		$a3 = { 0F 85 51 FF FF FF 61 C9 C2 10 00 }
		$a4 = { EB F2 5E 59 5B 58 C9 C2 10 00 }
				$a5 = { EB F0 5E 59 5B 58 C9 C2 20 00 }
		$a6 = { 80 3B CC 75 19 C6 03 00 }
	condition:
				for any i in (0..pe.number_of_sections - 1):
		(  $a0 in (pe.sections[i].raw_data_offset..pe.sections[i].raw_data_offset+0x50)  )
		and ($a1 or $a2)
		and ($a3 or $a4 or $a5 or $a6)
		
}