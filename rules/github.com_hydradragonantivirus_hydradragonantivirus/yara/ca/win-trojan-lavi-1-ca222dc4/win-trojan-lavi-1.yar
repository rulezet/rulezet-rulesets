rule Win_Trojan_LAVI_1
{
strings:
	$a0 = { ffb9390681e91d01268a0289f6340080ec0089f62688024605000083e900e2e888db050000c3 }


condition:
	$a0
}