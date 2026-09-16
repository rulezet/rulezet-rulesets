rule Win_Trojan_Replico_5
{
strings:
	$a0 = { 3701b9a2012e8ab6f1022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}