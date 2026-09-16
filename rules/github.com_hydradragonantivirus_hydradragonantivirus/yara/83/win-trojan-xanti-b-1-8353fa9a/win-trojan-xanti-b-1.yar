rule Win_Trojan_Xanti_b_1
{
strings:
	$a0 = { a4c686cb0206b41a8d96a002cd21b82435cd21899e9c028c86 }


condition:
	$a0
}