rule Win_Trojan_Jktk_1
{
strings:
	$a0 = { 07be007cbf0001b90002fcf2a4 }


condition:
	$a0
}