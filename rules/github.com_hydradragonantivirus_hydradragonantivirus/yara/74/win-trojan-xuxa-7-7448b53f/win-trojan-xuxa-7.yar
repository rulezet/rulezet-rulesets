rule Win_Trojan_Xuxa_7
{
strings:
	$a0 = { 74342e8a96a1078db65900b948072ed20452eb01 }


condition:
	$a0
}