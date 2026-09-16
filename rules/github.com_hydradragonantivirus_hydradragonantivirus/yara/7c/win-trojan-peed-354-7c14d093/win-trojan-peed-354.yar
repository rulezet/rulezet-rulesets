rule Win_Trojan_Peed_354
{
strings:
	$a0 = { 81fbf0ad0b007f6dc21a00ab50525131c089c15151ff1544834000055008000093 }


condition:
	$a0
}