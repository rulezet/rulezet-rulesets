rule Win_Trojan_Lemming_2
{
strings:
	$a0 = { 1801e800005d81ed09012e803251e3044946ebf6 }


condition:
	$a0
}