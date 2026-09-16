rule Win_Trojan_Hungry_1
{
strings:
	$a0 = { d6b4402e8b9c3d00b979020e1fcd212e8b8476002d0300 }


condition:
	$a0
}