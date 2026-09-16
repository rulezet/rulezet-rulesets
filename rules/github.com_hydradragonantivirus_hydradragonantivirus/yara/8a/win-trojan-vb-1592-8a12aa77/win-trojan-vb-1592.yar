rule Win_Trojan_VB_1592
{
strings:
	$a0 = { 6f766572617465000000000000000050000000dff52b679d12654c8f6ccb039ab674be }


condition:
	$a0
}