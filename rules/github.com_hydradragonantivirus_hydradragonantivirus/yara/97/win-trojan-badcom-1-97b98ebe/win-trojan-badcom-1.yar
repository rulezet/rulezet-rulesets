rule Win_Trojan_BadCOM_1
{
strings:
	$a0 = { ba00015903d151b92d02cd21bf01035903f951b92600 }


condition:
	$a0
}