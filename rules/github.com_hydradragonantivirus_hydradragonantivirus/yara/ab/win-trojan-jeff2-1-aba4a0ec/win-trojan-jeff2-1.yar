rule Win_Trojan_Jeff2_1
{
strings:
	$a0 = { b800018ccb81c3e0005350cb }


condition:
	$a0
}