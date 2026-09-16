import "pe"
rule FSG200 : bart xt
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
				$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 }
	condition:
							($a0 at 0x1F2) and (pe.timestamp == 0x21475346) and (pe.entry_point == 0x154)
}