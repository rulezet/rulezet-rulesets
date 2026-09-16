rule Win_Trojan_Word_5
{
strings:
	$a0 = { be1d2880342c4681feef2d72 }


condition:
	$a0
}