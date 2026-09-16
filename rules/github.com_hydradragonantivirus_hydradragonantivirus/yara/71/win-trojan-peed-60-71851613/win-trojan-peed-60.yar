rule Win_Trojan_Peed_60
{
strings:
	$a0 = { 68bdcaffff81e8010000008d6c200083c5fe83c5 }


condition:
	$a0
}