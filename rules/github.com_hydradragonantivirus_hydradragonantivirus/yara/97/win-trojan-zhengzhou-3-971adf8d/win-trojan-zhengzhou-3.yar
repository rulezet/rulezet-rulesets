rule Win_Trojan_ZhengZhou_3
{
strings:
	$a0 = { 4c00be007cbf000bb90002fcf3a433c0cd13b80502bb0001b90300ba8000cd13b85a0b50 }


condition:
	$a0
}