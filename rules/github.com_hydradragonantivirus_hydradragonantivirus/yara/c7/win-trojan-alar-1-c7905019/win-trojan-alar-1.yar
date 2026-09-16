rule Win_Trojan_Alar_1
{
strings:
	$a0 = { b000e670fb0bdb7401cf33c08ec026a113042d0a0026a31304b94000f7e1408ec02d10005033dbb8 }


condition:
	$a0
}