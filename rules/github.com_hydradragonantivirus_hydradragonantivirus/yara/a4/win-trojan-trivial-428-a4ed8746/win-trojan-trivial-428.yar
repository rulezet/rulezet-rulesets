rule Win_Trojan_Trivial_428
{
strings:
	$a0 = { ffcd213d01017415b44eb92700ba8d01cd217215e81d007504b44febf3b409 }


condition:
	$a0
}