rule Win_Trojan_Small_5386
{
strings:
	$a0 = { 56e9[0-255]ff74241c5b81eb010000008d041885c0 }


condition:
	$a0
}