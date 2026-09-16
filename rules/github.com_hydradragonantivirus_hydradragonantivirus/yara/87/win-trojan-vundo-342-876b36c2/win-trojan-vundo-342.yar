rule Win_Trojan_Vundo_342
{
strings:
	$a0 = { e80?000000[0-10]5fbe??(00|01)0000[0-10]03fe[0-10]8b3f[0-25]3bfe77[0-10]cd20 }


condition:
	$a0
}