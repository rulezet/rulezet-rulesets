rule Win_Trojan_Crypt_235
{
strings:
	$a0 = { 558becb8bc6e76ecbb9fa2ed6d50e800000000582da81a }


condition:
	$a0
}