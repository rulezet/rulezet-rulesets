rule Win_Trojan_Ninecomp_1
{
strings:
	$a0 = { 5bbe110003f3b9aa0289f7ac30d8aae2 }


condition:
	$a0
}