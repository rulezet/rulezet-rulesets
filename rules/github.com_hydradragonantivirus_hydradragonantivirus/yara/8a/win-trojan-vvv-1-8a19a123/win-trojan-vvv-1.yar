rule Win_Trojan_VVV_1
{
strings:
	$a0 = { d8b4408b0efc00030efa008b16f800cd21 }


condition:
	$a0
}