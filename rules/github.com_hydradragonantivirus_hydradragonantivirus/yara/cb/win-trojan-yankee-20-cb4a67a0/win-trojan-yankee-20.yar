rule Win_Trojan_Yankee_20
{
strings:
	$a0 = { eb02b43fe8090072023bc1c332c0b4422e8b1e3a00cd }


condition:
	$a0
}