rule Win_Trojan_Crypt_185
{
strings:
	$a0 = { b800000000600bc07468e8000000005805530000008038e9751361eb45db2d37104a00ffffffffffff }


condition:
	$a0
}