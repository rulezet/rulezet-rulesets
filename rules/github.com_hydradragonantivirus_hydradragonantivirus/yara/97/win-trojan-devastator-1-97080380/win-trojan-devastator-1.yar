rule Win_Trojan_Devastator_1
{
strings:
	$a0 = { 58803e0301007410bb1a01438a160301301781fbad0175f3 }


condition:
	$a0
}