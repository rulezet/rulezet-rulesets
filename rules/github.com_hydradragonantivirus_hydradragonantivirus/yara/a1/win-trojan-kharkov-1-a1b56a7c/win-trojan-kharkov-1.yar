rule Win_Trojan_Kharkov_1
{
strings:
	$a0 = { da8ed8a184000bc075038edacbfa832e }


condition:
	$a0
}