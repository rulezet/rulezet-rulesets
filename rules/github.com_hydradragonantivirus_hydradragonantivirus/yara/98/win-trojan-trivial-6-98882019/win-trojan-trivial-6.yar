rule Win_Trojan_Trivial_6
{
strings:
	$a0 = { 2a2e2a00b44e8bd1cd21b43cba9e00cd21b74087d193ebf7 }


condition:
	$a0
}