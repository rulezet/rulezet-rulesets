rule Win_Trojan_USSR_1
{
strings:
	$a0 = { b97d07bf2d0003fe2e300547e2fa }


condition:
	$a0
}