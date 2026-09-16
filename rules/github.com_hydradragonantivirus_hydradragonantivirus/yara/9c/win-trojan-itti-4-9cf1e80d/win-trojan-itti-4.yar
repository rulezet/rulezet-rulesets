rule Win_Trojan_Itti_4
{
strings:
	$a0 = { b44eb92700ba5d01cd21720ee816007504b44febf3b8014ccd21 }


condition:
	$a0
}