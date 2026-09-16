rule Win_Trojan_USSR_6
{
strings:
	$a0 = { b99906b80040e8f7fd72203d9906751b33c933d2b80042e8e6fd }


condition:
	$a0
}