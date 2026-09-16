rule Win_Trojan_Delf_1620
{
strings:
	$a0 = { 6a008d45ecb92c3a40008b1568564000e8d3f6ffff8b45ece84ff7ffff50e855fcffff33c05a595964891068bc3940008d45ece888f5ffffc3 }


condition:
	$a0
}