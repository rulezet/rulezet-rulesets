rule Win_Trojan_F_31
{
strings:
	$a0 = { e800005b81c347f0b9a80f2e310f2e8137d5d543e2f3 }


condition:
	$a0
}