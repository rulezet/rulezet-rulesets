rule Win_Trojan_Gen_19
{
strings:
	$a0 = { 03bfb2035733f681c50001e88701b440b9c1045acd21b80042e84000b440b90400ba2003cd21 }


condition:
	$a0
}