rule Win_Trojan_Skuns_1
{
strings:
	$a0 = { 9a000085005589e5b802029acd02850081ec0202bfb4020e57bfae2c1e57b80500509a0f088500c606b42c27bfba020e }


condition:
	$a0
}