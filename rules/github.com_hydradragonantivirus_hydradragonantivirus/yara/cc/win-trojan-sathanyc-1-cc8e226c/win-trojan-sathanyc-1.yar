rule Win_Trojan_Sathanyc_1
{
strings:
	$a0 = { 3a5222110a0619453841290a435a1908 }


condition:
	$a0
}