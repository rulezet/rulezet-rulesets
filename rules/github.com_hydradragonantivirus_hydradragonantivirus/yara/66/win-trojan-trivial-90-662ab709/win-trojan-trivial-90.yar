rule Win_Trojan_Trivial_90
{
strings:
	$a0 = { 2a2e2a00b44e89f2cd21b43cba9e00cd2193b440 }


condition:
	$a0
}