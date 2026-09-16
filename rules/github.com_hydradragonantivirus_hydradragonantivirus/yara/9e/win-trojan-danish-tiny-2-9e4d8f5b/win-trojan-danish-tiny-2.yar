rule Win_Trojan_Danish_Tiny_2
{
strings:
	$a0 = { 408d940501b91e01cd219c9d7201c3e98e00 }


condition:
	$a0
}