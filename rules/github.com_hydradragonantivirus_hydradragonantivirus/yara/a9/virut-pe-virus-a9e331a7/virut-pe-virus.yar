import "pe"
rule Virut_PE_Virus
{
	meta:
		author="_pusher_"
		date = "2016-07"
		description="PE Virus"
	strings:
		$a0 = { E8 00 00 00 00 55 8B 5C 24 08 8B 6C 24 04 81 6C 24 04 ?? ?? ?? 00 81 E3 00 F0 FF FF 81 ED 05 10 40 00 81 7B 4E 54 68 69 73 75 0C 8B 43 3C 03 C3 66 81 38 50 45 74 08 81 EB 00 01 00 00 EB E3 8B 50 78 03 D3 8B 72 20 8B 4A 18 03 F3 51 AD 03 C3 81 78 FF 00 47 65 74 75 1B 81 78 03 50 72 6F 63 75 12 81 78 07 41 64 64 72 75 09 81 78 0B 65 73 73 00 74 05 E2 D7 59 5D C3 }
		$aa1 = "{NThisu"
		$aa2 = "Procu"
		$aa3 = "Addru"
		$aa4 = "Getu"
		$aa5 = "CreateEventA"
	condition:
		($a0 at pe.entry_point) or
		(
		4 of ($aa*) and
		uint32(0x20) == 0x20202020
		)
		
}