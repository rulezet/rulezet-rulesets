rule Win_Trojan_C_307
{
strings:
	$a0 = { 6858a84000e8eeffffff00000000000030 }

	$a1 = { 284c656e285642535f6a6f696e65720029203d2031 }


condition:
	$a0 and $a1
}