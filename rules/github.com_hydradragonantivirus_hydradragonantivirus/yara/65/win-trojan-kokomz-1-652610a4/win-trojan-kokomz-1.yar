rule Win_Trojan_Kokomz_1
{
strings:
	$a0 = { a76235731db829ab2b01d77f60d07f4d7a6e546f6f6c7a65ffcc31 }


condition:
	$a0
}