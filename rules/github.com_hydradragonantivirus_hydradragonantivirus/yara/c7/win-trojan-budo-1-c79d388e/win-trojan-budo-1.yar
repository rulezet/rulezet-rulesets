rule Win_Trojan_Budo_1
{
strings:
	$a0 = { 21be0001b96400bf4d018a04880547462eff06b701e2f352b4402e8b1ebb01b96400ba4d01cd21 }


condition:
	$a0
}