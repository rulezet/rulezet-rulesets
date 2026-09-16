rule Win_Trojan_Evasor_5
{
strings:
	$a0 = { 8db670018bfee80300eb4a90acf6d8c0c804f6d0c0 }


condition:
	$a0
}