rule Win_Trojan_Vundo_326
{
strings:
	$a0 = { e80?000000[0-10]5fba??(00|01)0000[0-10]03fa[0-10]8b3f[0-25]3bfa77[0-10]cd20 }


condition:
	$a0
}