rule Win_Trojan_Ouse_1
{
strings:
	$a0 = { 2acd2181f9c70772203e3ab68f0072193e3a968e007512b0028d1e9000b90100ba0000cd269de9 }


condition:
	$a0
}