rule Win_Trojan_F_8
{
strings:
	$a0 = { 012e8a242e32264d012e88244681fe9f0575ee585ec3 }


condition:
	$a0
}