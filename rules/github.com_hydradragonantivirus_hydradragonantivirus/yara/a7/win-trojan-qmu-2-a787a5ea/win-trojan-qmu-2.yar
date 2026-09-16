rule Win_Trojan_QMU_2
{
strings:
	$a0 = { 538bdab00043380775fbb84f4d3947 }


condition:
	$a0
}