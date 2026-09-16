rule Win_Trojan_Renos_5
{
strings:
	$a0 = { e892000000fd841a0000000c003f9700004078009300007d0000fa7332 }


condition:
	$a0
}