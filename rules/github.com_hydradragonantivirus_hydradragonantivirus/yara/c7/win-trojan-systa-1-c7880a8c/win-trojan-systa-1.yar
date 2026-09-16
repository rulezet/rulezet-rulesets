rule Win_Trojan_Systa_1
{
strings:
	$a0 = { b42fcd21899c????8c84????b41a8d94????cd21b44eb903008d94e200cd21 }


condition:
	$a0
}