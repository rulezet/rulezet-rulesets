rule Win_Trojan_Mamut_1
{
strings:
	$a0 = { 558bec83c4ec5356578d75fc8b44241490250000ffff81384d5a900074072d00100000ebf1 }


condition:
	$a0
}