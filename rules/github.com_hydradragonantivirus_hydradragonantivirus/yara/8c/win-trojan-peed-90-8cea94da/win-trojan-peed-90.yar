rule Win_Trojan_Peed_90
{
strings:
	$a0 = { 68bdcaffff81e8010000008d6c2000e9 }


condition:
	$a0
}