rule Win_Trojan_Small_4325
{
strings:
	$a0 = { 5657[0-255]8d2dfc??????e8??0000006a006a006a00 }


condition:
	$a0
}