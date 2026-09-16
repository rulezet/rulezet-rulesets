rule Win_Trojan_Vundo_341
{
strings:
	$a0 = { e80?000000[0-10]59ba??(00|01)0000[0-10]03ca[0-10]8b09[0-25]3bca77[0-10]cd20 }


condition:
	$a0
}