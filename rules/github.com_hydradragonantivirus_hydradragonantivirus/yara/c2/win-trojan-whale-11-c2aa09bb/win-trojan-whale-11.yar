rule Win_Trojan_Whale_11
{
strings:
	$a0 = { 1fe8f7ff81eba323b9c1118b174343 }


condition:
	$a0
}