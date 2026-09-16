rule Win_Trojan_Crasher_2
{
strings:
	$a0 = { 0e00cbb8ddddcd213ddada7503eb7e90b8210580c4 }


condition:
	$a0
}