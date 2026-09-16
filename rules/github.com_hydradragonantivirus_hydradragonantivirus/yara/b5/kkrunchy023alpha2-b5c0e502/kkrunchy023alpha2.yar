import "pe"
rule kkrunchy023alpha2 : Ryg
{
	meta:
		author="_pusher_"
		date = "2015-12"
	strings:
		$a0 = { 4D 5A 66 61 72 62 72 61 75 73 63 68 50 45 00 00 4C 01 01 00 }
		$a1 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	condition:
		$a0 at 0 and
		$a1 at pe.entry_point
}