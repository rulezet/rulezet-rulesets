rule Win_Trojan_Hellfire_12
{
strings:
	$a0 = { be03018bfeb9????ad35????abe2f9c3 }


condition:
	$a0
}