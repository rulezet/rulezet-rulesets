rule Win_Trojan_Keypress_5
{
strings:
	$a0 = { c7070100f9f51fc3f606180101740d8cc00510000106 }


condition:
	$a0
}