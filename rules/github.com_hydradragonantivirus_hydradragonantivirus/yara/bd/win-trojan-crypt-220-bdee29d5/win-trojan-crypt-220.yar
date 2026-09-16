rule Win_Trojan_Crypt_220
{
strings:
	$a0 = { f9720e5ccbfa3846ebfe3657c1cf3242c0e85b0000006081c689cc500d61def6ab852ebea129 }


condition:
	$a0
}