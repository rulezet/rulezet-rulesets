rule Win_Trojan_Vundo_335
{
strings:
	$a0 = { e80?000000[0-10]5bba??(00|01)0000[0-10]03da[0-10]8b1b[0-25]3bda77[0-10]cd20 }


condition:
	$a0
}