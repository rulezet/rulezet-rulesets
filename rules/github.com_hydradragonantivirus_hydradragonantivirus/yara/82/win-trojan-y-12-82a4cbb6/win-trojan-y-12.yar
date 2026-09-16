rule Win_Trojan_Y_12
{
strings:
	$a0 = { e800005d83ed03fcb85a5acd213d4f4775450e1f8db63b00b462cd218cc839c3538ec3741e83c310015c02015c04 }


condition:
	$a0
}