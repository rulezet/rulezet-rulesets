rule Win_Trojan_Crypt_192
{
strings:
	$a0 = { 6a046a006a0068fffffbffff15b830480085c07e086a00ff1594304800a19911480031059111480031 }


condition:
	$a0
}