rule Win_Trojan_BOO_3
{
strings:
	$a0 = { 50cbbfc000e8450033c0cd1a81c2220283d1008bf28bf933c0cd1a3bcf7cf877043bd67cf2 }


condition:
	$a0
}