rule Win_Trojan_Vesna_4
{
strings:
	$a0 = { 0690bb4d072e8a3732f42e88374be2f5c340e8ac0560e8e3ff61ba00018a261f01b94e0690cd }


condition:
	$a0
}