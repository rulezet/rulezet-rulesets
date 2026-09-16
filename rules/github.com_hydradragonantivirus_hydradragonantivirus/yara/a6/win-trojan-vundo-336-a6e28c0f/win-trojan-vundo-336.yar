rule Win_Trojan_Vundo_336
{
strings:
	$a0 = { e80?000000[0-10]5abb??(00|01)0000[0-10]03d3[0-10]8b12[0-25]3bd377[0-10]cd20 }


condition:
	$a0
}