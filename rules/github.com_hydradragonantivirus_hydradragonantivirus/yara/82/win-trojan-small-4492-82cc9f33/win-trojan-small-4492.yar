rule Win_Trojan_Small_4492
{
strings:
	$a0 = { e84f000000c3eb6181c5ff19f7ff83f5ff01ddeb4a81efdc07000089f8eb5d55 }


condition:
	$a0
}