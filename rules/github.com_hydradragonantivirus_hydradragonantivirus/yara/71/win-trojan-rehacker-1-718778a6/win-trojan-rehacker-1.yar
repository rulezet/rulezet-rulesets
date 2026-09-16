rule Win_Trojan_Rehacker_1
{
strings:
	$a0 = { 736b7970656d6f6f642e657865 }


condition:
	$a0
}