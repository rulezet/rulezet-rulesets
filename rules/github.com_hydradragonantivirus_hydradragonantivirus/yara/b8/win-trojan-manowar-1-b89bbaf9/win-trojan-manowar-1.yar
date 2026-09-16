rule Win_Trojan_Manowar_1
{
strings:
	$a0 = { cd218bd3061fb8ec25cd212ea19d04 }


condition:
	$a0
}