rule Win_Trojan_Trivial_285
{
strings:
	$a0 = { 3001b41acd21ba2801b44eb90700cd217214ba4e01b8023dcd218bd8b92e00ba0001b440cd21c3 }


condition:
	$a0
}