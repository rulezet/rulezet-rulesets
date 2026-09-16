rule Win_Trojan_Int86_2
{
strings:
	$a0 = { cd21813e7c021e03754db452cd210653268b4714a3 }


condition:
	$a0
}