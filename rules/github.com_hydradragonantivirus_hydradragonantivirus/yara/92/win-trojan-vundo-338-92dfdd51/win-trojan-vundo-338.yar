rule Win_Trojan_Vundo_338
{
strings:
	$a0 = { e80?000000[0-10]5fb9??(00|01)0000[0-10]03f9[0-10]8b3f[0-25]3bf977[0-10]cd20 }


condition:
	$a0
}