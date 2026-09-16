rule Win_Trojan_QMU_1
{
strings:
	$a0 = { 8bdab00043380775fbb84f4d3947fe7404f9eb0290f8 }


condition:
	$a0
}