rule Win_Adware_Lop_178
{
strings:
	$a0 = { adb7a77e3ba683dc476b781ba83f30d234535d279bc0e083e2e72fc9f67156fe7a370ef530fc64aa409e8a2f8ecb41720052439752882432aa32e081 }


condition:
	$a0
}