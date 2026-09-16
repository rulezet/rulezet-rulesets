rule Win_Trojan_Rainbow_8
{
strings:
	$a0 = { cd133dedde75460e1f81c62708813c4d5a7409bf00 }


condition:
	$a0
}