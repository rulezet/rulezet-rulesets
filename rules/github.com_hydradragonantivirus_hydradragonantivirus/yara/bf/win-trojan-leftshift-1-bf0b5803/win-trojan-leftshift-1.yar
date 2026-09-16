rule Win_Trojan_LeftShift_1
{
strings:
	$a0 = { 7800c6470420501f5007800e900420bb0007b99064ba8003bf0200b400cd13b80202cd13 }


condition:
	$a0
}