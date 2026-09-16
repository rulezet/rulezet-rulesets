rule Win_Trojan_Whale_7
{
strings:
	$a0 = { e80100c359bb61dc01cb0eb9c3101ffe }


condition:
	$a0
}