rule Win_Trojan_Trojan_227
{
strings:
	$a0 = { a4c686f30202b41a8d96c802cd21b82435cd21899ec4028c86 }


condition:
	$a0
}