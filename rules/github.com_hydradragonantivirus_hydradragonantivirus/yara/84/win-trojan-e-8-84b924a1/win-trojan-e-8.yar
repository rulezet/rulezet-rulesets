rule Win_Trojan_E_8
{
strings:
	$a0 = { e751ef6666e751e36666e751ed6666de6a67d9e76694c3de1666d9ea66cb55a3cd859dec9cdf8c19 }


condition:
	$a0
}