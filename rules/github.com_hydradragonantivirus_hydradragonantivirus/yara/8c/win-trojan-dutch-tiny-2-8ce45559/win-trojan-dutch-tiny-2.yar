rule Win_Trojan_Dutch_Tiny_2
{
strings:
	$a0 = { 94c901b4408d940501b9bf00cd217215 }


condition:
	$a0
}