rule Win_Trojan_Phardera_3
{
strings:
	$a0 = { 01010055ed0000000001000903000089060000030000000903 }


condition:
	$a0
}