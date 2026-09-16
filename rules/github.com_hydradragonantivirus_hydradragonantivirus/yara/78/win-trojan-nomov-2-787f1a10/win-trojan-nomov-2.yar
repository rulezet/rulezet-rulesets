rule Win_Trojan_Nomov_2
{
strings:
	$a0 = { 6f790d0ae80101502de2ff92e89dff2d060086e0fec05005ff0583e907cd215850cd219358 }


condition:
	$a0
}