rule Upack033alphaDwing
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
				$a1 = { 4D 5A 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 50 45 }
	condition:
				$a1 at 0 
}