rule Win_Trojan_Fathom_1
{
strings:
	$a0 = { e8??000000030683c60481f0????????8d7efcab39f375 }


condition:
	$a0
}