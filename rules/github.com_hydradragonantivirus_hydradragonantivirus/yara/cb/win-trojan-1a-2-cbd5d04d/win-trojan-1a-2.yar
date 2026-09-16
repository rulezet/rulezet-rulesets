rule Win_Trojan_1a_2
{
strings:
	$a0 = { a5c686df0401b41a8d96b404cd21b447b2008db6 }


condition:
	$a0
}