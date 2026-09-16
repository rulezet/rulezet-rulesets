rule Win_Trojan_SGU_2
{
strings:
	$a0 = { 6840fa041068dc2004108d85f8feffff50e8f8e3ffff83c40c8d85f8feffff508b0d6cfb041051e8c0ddffff83c408 }


condition:
	$a0
}