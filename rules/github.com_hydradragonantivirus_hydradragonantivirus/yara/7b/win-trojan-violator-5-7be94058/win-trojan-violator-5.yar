rule Win_Trojan_Violator_5
{
strings:
	$a0 = { 02eb9e8b848800241e3c1e74ee81 }


condition:
	$a0
}