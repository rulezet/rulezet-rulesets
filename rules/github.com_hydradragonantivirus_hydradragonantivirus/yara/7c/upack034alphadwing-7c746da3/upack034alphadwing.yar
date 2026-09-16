import "pe"
rule Upack034alphaDwing
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { BE E8 11 40 00 AD 50 AD 50 66 BE 58 01 6A 12 BF ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 10 00 00 D7 11 00 00 00 00 00 00 00 00 00 00 00 00 2A 10 00 00 E8 11 00 }
			condition:
		$a0 at pe.entry_point 
		}