rule Win_Trojan_Xany_4
{
strings:
	$a0 = { b000e85cff8bd5b9d303e864ffc686020401f8c3 }


condition:
	$a0
}