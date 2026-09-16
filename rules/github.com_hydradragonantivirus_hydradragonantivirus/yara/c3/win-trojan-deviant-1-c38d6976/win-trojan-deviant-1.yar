rule Win_Trojan_Deviant_1
{
strings:
	$a0 = { cd21b4408d960701b9a601cd21b801573e8b8e51 }


condition:
	$a0
}