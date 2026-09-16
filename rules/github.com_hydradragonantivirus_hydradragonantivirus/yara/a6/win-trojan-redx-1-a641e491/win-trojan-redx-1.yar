rule Win_Trojan_Redx_1
{
strings:
	$a0 = { ee0301e81a00e81700e8d2018d9c }


condition:
	$a0
}