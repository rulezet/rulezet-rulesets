rule Win_Trojan_Chromosome_1
{
strings:
	$a0 = { b43eccb8014333c92e8a8eae028d96b702ccfe869702e9 }


condition:
	$a0
}