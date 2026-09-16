rule Win_Trojan_Kerplunk_3059_1
{
strings:
	$a0 = { ed03000e0e1f078dbe20008d96a60bffd28db62d00 }


condition:
	$a0
}