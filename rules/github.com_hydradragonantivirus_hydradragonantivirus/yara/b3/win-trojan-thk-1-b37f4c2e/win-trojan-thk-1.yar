rule Win_Trojan_Thk_1
{
strings:
	$a0 = { bb03a3bd03e8a300b44eb120bac903cd21b8013dba9e00cd2193b440b90004ba0001cd21e86601 }


condition:
	$a0
}