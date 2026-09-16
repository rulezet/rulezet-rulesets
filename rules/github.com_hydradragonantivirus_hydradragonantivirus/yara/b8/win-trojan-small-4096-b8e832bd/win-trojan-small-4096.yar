rule Win_Trojan_Small_4096
{
strings:
	$a0 = { e82e0000000f34e83f000000c21000e80200000052c383042408ebf805386762 }


condition:
	$a0
}