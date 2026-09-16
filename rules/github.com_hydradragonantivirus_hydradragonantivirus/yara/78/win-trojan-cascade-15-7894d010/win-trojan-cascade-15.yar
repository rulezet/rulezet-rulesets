rule Win_Trojan_Cascade_15
{
strings:
	$a0 = { e800005b81eb3101f6872a0101740f8db74d01bc82 }


condition:
	$a0
}