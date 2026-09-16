rule Win_Trojan_Vundo_333
{
strings:
	$a0 = { e80?000000[0-10]5fbb??(00|01)0000[0-10]03fb[0-10]8b3f[0-25]3bfb77[0-10]cd20 }


condition:
	$a0
}