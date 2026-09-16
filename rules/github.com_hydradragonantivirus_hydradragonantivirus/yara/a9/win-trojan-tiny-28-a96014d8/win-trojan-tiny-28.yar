rule Win_Trojan_Tiny_28
{
strings:
	$a0 = { 5cfec587f1b9eeeef3a4b44eb15687d1fec6cd217301cbb8023d99b29ecd2193b43fb25cfec654 }


condition:
	$a0
}