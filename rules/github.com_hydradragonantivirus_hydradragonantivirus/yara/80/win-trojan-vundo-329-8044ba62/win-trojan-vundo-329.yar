rule Win_Trojan_Vundo_329
{
strings:
	$a0 = { e80?000000[0-10]59bb??(00|01)0000[0-10]03cb[0-10]8b09[0-25]3bcb77[0-10]cd20 }


condition:
	$a0
}