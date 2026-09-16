rule Win_Trojan_Small_5384
{
strings:
	$a0 = { 56e9[0-255]89e38d9b1c0000008b1bffcb01d885c00f841700000083c8ff }


condition:
	$a0
}