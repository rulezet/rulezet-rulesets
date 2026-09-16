rule Win_Trojan_Adolph_2
{
strings:
	$a0 = { b91e00ba7d04b43fcd217246a112 }


condition:
	$a0
}