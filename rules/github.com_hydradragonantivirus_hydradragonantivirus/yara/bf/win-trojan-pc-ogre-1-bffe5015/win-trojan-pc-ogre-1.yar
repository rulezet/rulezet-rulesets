rule Win_Trojan_PC_Ogre_1
{
strings:
	$a0 = { d2cd218a078b57108b4f0b2bca4933db8edbcd26581f8d160301b409cd21cd20b41a8b162f }


condition:
	$a0
}