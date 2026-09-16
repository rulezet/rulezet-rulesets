rule Win_Trojan_Hellfire_7
{
strings:
	$a0 = { be03018bfeb9??02adeb04abe2fac335????73f7 }


condition:
	$a0
}