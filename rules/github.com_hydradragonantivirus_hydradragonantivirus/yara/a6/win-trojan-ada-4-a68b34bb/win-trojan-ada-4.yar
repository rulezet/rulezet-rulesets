rule Win_Trojan_Ada_4
{
strings:
	$a0 = { 0cb8004bbab012cd21b402b207cd }


condition:
	$a0
}