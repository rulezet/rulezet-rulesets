rule Win_Trojan_WhaleMutant_4
{
strings:
	$a0 = { 118b0743430107e2fa81c39200807f010174e106 }


condition:
	$a0
}