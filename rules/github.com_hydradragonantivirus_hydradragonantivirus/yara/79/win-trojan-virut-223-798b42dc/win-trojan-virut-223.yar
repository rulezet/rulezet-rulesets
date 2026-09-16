rule Win_Trojan_Virut_223
{
strings:
	$a0 = { e800000000558b5c2408908b6c2404816c2404 }


condition:
	$a0
}