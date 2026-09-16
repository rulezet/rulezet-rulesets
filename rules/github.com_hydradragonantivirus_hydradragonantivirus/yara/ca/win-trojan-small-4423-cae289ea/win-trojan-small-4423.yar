rule Win_Trojan_Small_4423
{
strings:
	$a0 = { 8d05????4000505068????0f00e86a00000051 }


condition:
	$a0
}