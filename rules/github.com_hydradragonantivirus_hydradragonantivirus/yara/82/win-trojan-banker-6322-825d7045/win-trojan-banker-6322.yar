rule Win_Trojan_Banker_6322
{
strings:
	$a0 = { 558bec83c4f0b850f04800e88878f7ffa1681d49 }

	$a1 = { 4c6974746c6520426f6d626572732052657475726e73 }


condition:
	$a0 and $a1
}