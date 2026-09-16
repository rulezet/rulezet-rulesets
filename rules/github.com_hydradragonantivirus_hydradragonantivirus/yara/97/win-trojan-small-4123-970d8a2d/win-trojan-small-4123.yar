rule Win_Trojan_Small_4123
{
strings:
	$a0 = { 6a046a006a0068fffffbffff156c00470085c07e086a00ff1558004700 }


condition:
	$a0
}