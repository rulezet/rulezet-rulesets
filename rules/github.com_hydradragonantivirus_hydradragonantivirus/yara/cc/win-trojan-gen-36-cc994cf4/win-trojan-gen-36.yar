rule Win_Trojan_Gen_36
{
strings:
	$a0 = { cd217252b91e00ba7d04b43fcd217246 }


condition:
	$a0
}