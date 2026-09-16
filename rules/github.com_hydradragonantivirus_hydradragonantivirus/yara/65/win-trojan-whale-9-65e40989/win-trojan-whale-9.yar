rule Win_Trojan_Whale_9
{
strings:
	$a0 = { e82b0087d381c361dcb9c311e8e0fff6 }


condition:
	$a0
}