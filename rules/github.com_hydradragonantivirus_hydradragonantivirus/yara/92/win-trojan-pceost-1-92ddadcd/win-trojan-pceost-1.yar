rule Win_Trojan_PceOSt_1
{
strings:
	$a0 = { 3628010e901f2eff262601 }


condition:
	$a0
}