rule Win_Trojan_Poppins_1
{
strings:
	$a0 = { 01b91a00ac4892b406cd21e2f7bac501b824250106e4 }


condition:
	$a0
}