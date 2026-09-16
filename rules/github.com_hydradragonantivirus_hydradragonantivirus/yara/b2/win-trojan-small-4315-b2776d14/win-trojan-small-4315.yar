rule Win_Trojan_Small_4315
{
strings:
	$a0 = { e8??000000e9??000000e8??0000006639fee9??0000008d3405000000008d743300 }


condition:
	$a0
}