rule Win_Trojan_Formatc_2
{
strings:
	$a0 = { 666f726d6174202f7920633a }


condition:
	$a0
}