rule Win_Trojan_Nanite_1
{
strings:
	$a0 = { 3dcd21723b8bd8b94c01ba0001b440cd212e8b1e2901 }


condition:
	$a0
}