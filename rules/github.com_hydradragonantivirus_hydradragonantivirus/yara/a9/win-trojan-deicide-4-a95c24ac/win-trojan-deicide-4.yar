rule Win_Trojan_Deicide_4
{
strings:
	$a0 = { 02a328028b1e2e02891e2a02b41aba00f0cd21b44eb9 }


condition:
	$a0
}