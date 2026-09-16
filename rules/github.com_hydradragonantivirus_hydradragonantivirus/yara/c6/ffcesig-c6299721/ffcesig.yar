rule FFCESig
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings: 
		$a0 = { 60 8B 74 24 24 8B 7C 24 28 FC AD 33 C9 85 C0 74 11 33 D2 8D 1C 38 A4 B1 03 E8 72 00 00 00 73 F6 3B FB 0F 83 85 00 00 00 }
	condition:
		($a0)
}