rule Win_Trojan_Evul_4
{
strings:
	$a0 = { 16e800005d81ed1801e80300eb0f90b90701be31018032 }


condition:
	$a0
}