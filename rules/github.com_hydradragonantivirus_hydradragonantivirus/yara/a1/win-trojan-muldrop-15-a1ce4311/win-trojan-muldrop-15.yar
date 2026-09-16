rule Win_Trojan_Muldrop_15
{
strings:
	$a0 = { 920b402586b6fe8d76a37f5e8f67db32786334279b3146e86ed7c02e45b3d340a84f83 }


condition:
	$a0
}