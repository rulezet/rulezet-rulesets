rule Win_Trojan_Small_4284
{
strings:
	$a0 = { 60e85f0000006a9c6800800000e83c000000 }


condition:
	$a0
}