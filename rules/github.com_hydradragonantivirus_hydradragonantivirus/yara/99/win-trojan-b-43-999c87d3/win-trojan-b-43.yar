rule Win_Trojan_B_43
{
strings:
	$a0 = { d0bc007cbb587da14c003bc3742da3af7da14e00a3b17dbf00048b451348894513b106d3e0 }


condition:
	$a0
}