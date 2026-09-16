rule Win_Trojan_Avcs_4
{
strings:
	$a0 = { e800005d81ed????8db6????568bfeb972008b96????fcad33c2ab84e8e2f8c3 }


condition:
	$a0
}