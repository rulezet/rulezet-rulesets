rule Win_Trojan_Bops_1
{
strings:
	$a0 = { a16c0426a3cd041f06b82435cdfe891ed3048c06d504 }


condition:
	$a0
}