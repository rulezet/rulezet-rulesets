rule Win_Trojan_Small_4431
{
strings:
	$a0 = { 6a00c70424??3042008d04240f6e100f }


condition:
	$a0
}