rule Win_Trojan_LJF_1
{
strings:
	$a0 = { ffcd213daa55746d26812e0200c00026a102008cc149 }


condition:
	$a0
}