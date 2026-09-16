rule Win_Trojan_Sality_1015
{
strings:
	$a0 = { 60e8540000008dbd00104000b8????????03f88bf7509bdbe3 }


condition:
	$a0
}