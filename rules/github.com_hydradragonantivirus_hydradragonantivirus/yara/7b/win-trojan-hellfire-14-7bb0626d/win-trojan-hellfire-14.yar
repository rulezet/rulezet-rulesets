rule Win_Trojan_Hellfire_14
{
strings:
	$a0 = { be03018bfeb9????adeb0590abe2f9c335????73f7 }


condition:
	$a0
}