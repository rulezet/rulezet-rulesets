rule Win_Trojan_Cascade_21
{
strings:
	$a0 = { e800005b81eb0c018db71f01b988033134310c46e2f9 }


condition:
	$a0
}