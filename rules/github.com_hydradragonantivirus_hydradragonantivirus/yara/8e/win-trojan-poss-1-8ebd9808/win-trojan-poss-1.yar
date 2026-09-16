rule Win_Trojan_Poss_1
{
strings:
	$a0 = { be7f08894404c744028000894408c744065c0089440cc7440a6c00a18000890407b430cd21 }


condition:
	$a0
}