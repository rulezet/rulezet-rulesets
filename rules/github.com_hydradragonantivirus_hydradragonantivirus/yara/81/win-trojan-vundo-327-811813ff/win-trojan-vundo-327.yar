rule Win_Trojan_Vundo_327
{
strings:
	$a0 = { e80?000000[0-10]5ebb??(00|01)0000[0-10]03f3[0-10]8b36[0-25]3bf377[0-10]cd20 }


condition:
	$a0
}