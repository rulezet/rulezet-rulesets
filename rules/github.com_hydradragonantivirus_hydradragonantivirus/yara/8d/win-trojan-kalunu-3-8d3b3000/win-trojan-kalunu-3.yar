rule Win_Trojan_Kalunu_3
{
strings:
	$a0 = { b940028dbe????8bf7b41eac80f41332c4f6d0aae2f5c3 }


condition:
	$a0
}