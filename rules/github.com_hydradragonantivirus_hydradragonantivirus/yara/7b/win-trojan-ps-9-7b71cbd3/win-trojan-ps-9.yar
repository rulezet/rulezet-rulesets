rule Win_Trojan_PS_9
{
strings:
	$a0 = { 5e83ee??56fc81c6????bf0001a5a55e[1-100]8d94????b41acd21[1-100]8d94????b44eb93f00cd21 }


condition:
	$a0
}