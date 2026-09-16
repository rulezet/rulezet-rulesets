rule Win_Trojan_Hellfire_8
{
strings:
	$a0 = { be03018bfeb90f02adeb0590abe2f9c335????73f7 }


condition:
	$a0
}