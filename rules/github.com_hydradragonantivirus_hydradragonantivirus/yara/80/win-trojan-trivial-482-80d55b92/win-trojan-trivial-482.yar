rule Win_Trojan_Trivial_482
{
strings:
	$a0 = { 1a8d5680cd21b44eb927005acd217207e80d00b44febf5 }


condition:
	$a0
}