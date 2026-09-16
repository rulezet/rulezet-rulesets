rule Win_Trojan_Trivial_439
{
strings:
	$a0 = { b9c800ba0001cd21cd202a2e434f4d00627920141598 }


condition:
	$a0
}