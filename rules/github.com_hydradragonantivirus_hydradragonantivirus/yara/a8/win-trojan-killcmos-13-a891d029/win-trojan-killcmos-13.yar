rule Win_Trojan_KillCMOS_13
{
strings:
	$a0 = { b27032f6b02eee4232c0ee }


condition:
	$a0
}