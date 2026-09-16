rule Win_Trojan_Rubix_1
{
strings:
	$a0 = { be2d01bfa801e80100c3608bc63004463bf775f961c3 }


condition:
	$a0
}