rule Win_Trojan_Vundo_331
{
strings:
	$a0 = { e80?000000[0-10]5ab9??(00|01)0000[0-10]03d1[0-10]8b12[0-25]3bd177[0-10]cd20 }


condition:
	$a0
}