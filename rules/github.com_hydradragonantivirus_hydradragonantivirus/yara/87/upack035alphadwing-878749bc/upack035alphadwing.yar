import "pe"
rule Upack035alphaDwing
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$right = { 4D 5A 52 4A 66 33 D2 66 81 3A 4D 5A 75 F5 EB 08 50 45 00 00 4C 01 02 00 8B 5A 3C 8B 5C 1A 78 E9 80 01 00 00 E0 00 ?? ?? 0B 01 00 35 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
		$wrong = { 0B 01 4C 6F 61 64 4C }
	condition:
		$right at pe.entry_point 
		or $wrong at pe.entry_point
}