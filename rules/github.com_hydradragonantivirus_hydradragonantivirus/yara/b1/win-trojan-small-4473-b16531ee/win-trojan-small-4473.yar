rule Win_Trojan_Small_4473
{
strings:
	$a0 = { ff74241c588d80??????04506862343504e8590000004050ba81??????525051 }


condition:
	$a0
}