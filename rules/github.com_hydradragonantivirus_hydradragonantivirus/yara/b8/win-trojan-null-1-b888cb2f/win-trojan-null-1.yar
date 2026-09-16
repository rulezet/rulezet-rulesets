rule Win_Trojan_Null_1
{
strings:
	$a0 = { cd218b85a6013d90e9742d8b85d00150 }


condition:
	$a0
}