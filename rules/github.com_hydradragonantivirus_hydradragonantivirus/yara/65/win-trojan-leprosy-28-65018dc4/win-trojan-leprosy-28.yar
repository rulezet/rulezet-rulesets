rule Win_Trojan_Leprosy_28
{
strings:
	$a0 = { 3a014e8b1e3d0253e81400905bb987029090ba000190b44090cd21 }


condition:
	$a0
}