rule Win_Trojan_Small_4331
{
strings:
	$a0 = { 575355e8??000000e8??000000e8??000000[0-255]8d5c241c8b5c230081eb0100000001d885c0 }


condition:
	$a0
}