rule Win_Trojan_Peed_81
{
strings:
	$a0 = { 558bec83ec0ce869feffff85c07405e8 }


condition:
	$a0
}