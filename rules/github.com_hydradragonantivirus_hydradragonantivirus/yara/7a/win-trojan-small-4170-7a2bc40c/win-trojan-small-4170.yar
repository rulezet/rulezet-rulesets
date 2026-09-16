rule Win_Trojan_Small_4170
{
strings:
	$a0 = { cd2acd2acd2ae80000000031 }


condition:
	$a0
}