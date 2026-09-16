rule Win_Trojan_ToadG_1
{
strings:
	$a0 = { b8000026a39d02b419cd212ea2a902b447b600040188 }


condition:
	$a0
}