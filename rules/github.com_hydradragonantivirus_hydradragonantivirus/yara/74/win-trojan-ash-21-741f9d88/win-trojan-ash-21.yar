rule Win_Trojan_Ash_21
{
strings:
	$a0 = { b904008d960401cd2180be07011a74ca80be04014d74 }


condition:
	$a0
}