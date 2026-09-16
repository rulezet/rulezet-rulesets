rule Win_Trojan_Peed_211
{
strings:
	$a0 = { 8d0567451300ba75e42d0089c1714681e94432bb }


condition:
	$a0
}