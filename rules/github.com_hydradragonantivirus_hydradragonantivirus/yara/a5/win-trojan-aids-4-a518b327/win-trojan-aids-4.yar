rule Win_Trojan_AIDS_4
{
strings:
	$a0 = { 7509c47e0426c60500eb0fbf3f04 }


condition:
	$a0
}