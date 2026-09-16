rule Win_Trojan_Trivial_437
{
strings:
	$a0 = { b409ba8a01cd21b44eb90700ba5401cd217207e80900b44febf5b8014ccd21b43c33c9ba9e00cd2193b43fb90200 }


condition:
	$a0
}