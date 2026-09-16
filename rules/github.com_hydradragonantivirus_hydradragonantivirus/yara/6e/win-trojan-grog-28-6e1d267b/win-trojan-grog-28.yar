rule Win_Trojan_Grog_28
{
strings:
	$a0 = { 04be1201ad4e4704364e88044647e2f4 }


condition:
	$a0
}