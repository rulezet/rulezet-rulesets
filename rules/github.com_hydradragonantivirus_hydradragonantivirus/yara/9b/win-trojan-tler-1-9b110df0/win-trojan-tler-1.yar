rule Win_Trojan_Tler_1
{
strings:
	$a0 = { e83f00b440b9ac018d960401cd21e84500b8004233c933d2cd21b440b904008d962601cd21b80157 }


condition:
	$a0
}