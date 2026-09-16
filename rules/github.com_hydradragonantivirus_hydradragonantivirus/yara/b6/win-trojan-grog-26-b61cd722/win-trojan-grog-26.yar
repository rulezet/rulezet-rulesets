rule Win_Trojan_Grog_26
{
strings:
	$a0 = { d003be0e01ac04288844ffe2f8 }


condition:
	$a0
}