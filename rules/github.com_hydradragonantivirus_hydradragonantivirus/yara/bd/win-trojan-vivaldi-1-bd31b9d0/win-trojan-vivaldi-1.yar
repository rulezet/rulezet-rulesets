rule Win_Trojan_Vivaldi_1
{
strings:
	$a0 = { 0f95adb80040ba0000b900100e1fcd21 }


condition:
	$a0
}