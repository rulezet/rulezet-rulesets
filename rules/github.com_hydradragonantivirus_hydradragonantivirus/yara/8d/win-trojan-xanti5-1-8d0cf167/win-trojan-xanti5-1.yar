rule Win_Trojan_XANTI5_1
{
strings:
	$a0 = { a4c686cd0202b41a8d96a202cd21b82435cd21899e9e028c86 }


condition:
	$a0
}