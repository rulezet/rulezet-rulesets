rule Win_Trojan_Hung_1
{
strings:
	$a0 = { 011e57bf4f171e57b850135031c050509a6c058200bf5d011e57a1ba2a8b16bc2a2d050083da }


condition:
	$a0
}