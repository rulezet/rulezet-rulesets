rule Win_Trojan_Int19_1
{
strings:
	$a0 = { 0233c9b43ccd2193b440ba2f02b90200cd21b43ecd15b44eb9fe00ba2902cd217306cd20b44f }


condition:
	$a0
}