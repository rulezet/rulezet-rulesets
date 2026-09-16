rule Win_Trojan_Crypt_259
{
strings:
	$a0 = { 50e8d3fbffff88542c1890900f57e24590900f57e2884c341890900f }

	$a1 = { 44721b1b3c622fcfbd79d82a7a }


condition:
	$a0 and $a1
}