rule Win_Trojan_Bubbles_1
{
strings:
	$a0 = { b9c0012e8a272e3226dd022e882743e2f2c3 }


condition:
	$a0
}