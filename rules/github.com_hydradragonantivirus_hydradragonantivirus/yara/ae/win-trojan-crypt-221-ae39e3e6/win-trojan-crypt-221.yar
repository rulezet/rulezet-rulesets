rule Win_Trojan_Crypt_221
{
strings:
	$a0 = { 8d5d1981ef114c00008d75678d4d084081c6fe600000beac1040 }

	$a1 = { fd068d5a78583a889c43 }


condition:
	$a0 and $a1
}