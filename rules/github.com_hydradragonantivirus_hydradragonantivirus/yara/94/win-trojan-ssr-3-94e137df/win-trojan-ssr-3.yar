rule Win_Trojan_SSR_3
{
strings:
	$a0 = { 5e81ee03011e062e8a841e01b99907bf1f0103fe300547e2fbeb01 }


condition:
	$a0
}