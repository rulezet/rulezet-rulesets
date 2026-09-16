rule Win_Trojan_USSR_3
{
strings:
	$a0 = { 02b43fe8090072023bc1c332c0b4422e8b1e }


condition:
	$a0
}