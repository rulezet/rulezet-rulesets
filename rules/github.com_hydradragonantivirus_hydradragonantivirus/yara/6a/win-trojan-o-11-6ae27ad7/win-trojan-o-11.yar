rule Win_Trojan_O_11
{
strings:
	$a0 = { 7374616e646172642e6d6f766965737461722e }

	$a1 = { 6d3d226d6f7669657374617222 }

	$a2 = { 6d7367626f782028736d73672c }


condition:
	$a0 and $a1 and $a2
}