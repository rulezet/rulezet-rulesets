rule Win_Trojan_Small_5371
{
strings:
	$a0 = { e845000000e88e0000008d2d9f802700e86300000092e90a0000005656585f5e }


condition:
	$a0
}