rule Win_Trojan_Vundo_332
{
strings:
	$a0 = { e80?000000[0-10]5abe??(00|01)0000[0-10]03d6[0-10]8b12[0-25]3bd677[0-10]cd20 }


condition:
	$a0
}