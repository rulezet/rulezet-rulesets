rule Win_Trojan_Einm_1
{
strings:
	$a0 = { 340203de4bfec0feccf6d432c4433007e2f35bc3ba52 }


condition:
	$a0
}