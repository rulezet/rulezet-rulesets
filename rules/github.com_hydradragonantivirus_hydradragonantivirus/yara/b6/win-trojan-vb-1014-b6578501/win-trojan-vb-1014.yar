rule Win_Trojan_VB_1014
{
strings:
	$a0 = { 68f0854200e8f0ffffff00000000000030 }

	$a1 = { 436f6e7461637420537079 }


condition:
	$a0 and $a1
}