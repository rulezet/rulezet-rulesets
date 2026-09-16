rule Win_Trojan_Tiny_45
{
strings:
	$a0 = { cd32723893b000e83e00b43f8bfa }


condition:
	$a0
}