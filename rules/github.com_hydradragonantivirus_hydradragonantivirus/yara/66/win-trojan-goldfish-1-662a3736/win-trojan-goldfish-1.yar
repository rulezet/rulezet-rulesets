rule Win_Trojan_GoldFish_1
{
strings:
	$a0 = { 020055df010002000100c2060000b9030000040000000903 }


condition:
	$a0
}