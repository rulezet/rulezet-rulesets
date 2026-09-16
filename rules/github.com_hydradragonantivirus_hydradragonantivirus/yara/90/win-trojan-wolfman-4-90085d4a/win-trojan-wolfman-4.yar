rule Win_Trojan_Wolfman_4
{
strings:
	$a0 = { cd21b802428bcacd21b440590e1fba0001cd21b4 }


condition:
	$a0
}