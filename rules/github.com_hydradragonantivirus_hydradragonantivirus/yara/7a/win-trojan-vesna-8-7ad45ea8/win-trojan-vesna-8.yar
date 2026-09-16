rule Win_Trojan_Vesna_8
{
strings:
	$a0 = { 072e8a3732f42e88374be2f5c340e8300660e8e3ff61ba00018a263d01b9f00690cd2160e8d1 }


condition:
	$a0
}