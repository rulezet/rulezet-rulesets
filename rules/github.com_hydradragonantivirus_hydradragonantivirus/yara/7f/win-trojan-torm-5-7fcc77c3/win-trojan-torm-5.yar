rule Win_Trojan_Torm_5
{
strings:
	$a0 = { 1c00baca0003d6cd21727380bcca004d756381bcdc }


condition:
	$a0
}