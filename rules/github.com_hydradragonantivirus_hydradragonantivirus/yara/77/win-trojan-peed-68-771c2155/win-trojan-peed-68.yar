rule Win_Trojan_Peed_68
{
strings:
	$a0 = { fdfcbe78cc3d879081f6faaf7f87040056 }


condition:
	$a0
}