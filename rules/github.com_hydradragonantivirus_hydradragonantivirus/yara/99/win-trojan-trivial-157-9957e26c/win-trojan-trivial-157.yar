rule Win_Trojan_Trivial_157
{
strings:
	$a0 = { b44eb120ba1a01cd21b8023dba9e00cd2193b440ba0001cd21c3 }


condition:
	$a0
}