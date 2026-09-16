rule Win_Trojan_Dead_13
{
strings:
	$a0 = { b905008db6????bf0001f3a4b44eb907008d96????cd217303 }


condition:
	$a0
}