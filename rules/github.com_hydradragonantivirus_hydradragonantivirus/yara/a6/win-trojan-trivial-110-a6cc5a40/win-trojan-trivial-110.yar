rule Win_Trojan_Trivial_110
{
strings:
	$a0 = { 4eba1001cd21b43cba9e00cd21b21b2a2e2a00b74087d193ebf1 }


condition:
	$a0
}