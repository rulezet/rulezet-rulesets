rule Win_Trojan_AIDSII_1
{
strings:
	$a0 = { 4d5a8001100078002000970297026f02 }


condition:
	$a0
}