rule Win_Trojan_Trivial_88
{
strings:
	$a0 = { b44eb120ba8201cd21b8013dba9e00cd218bd8ba0001b9e500b440cd21b43ecd21b44fcd2173e2b42acd2180fe04740e80fe057409b409baad01cd21cd20b409 }


condition:
	$a0
}