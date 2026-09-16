rule Win_Trojan_Trivial_19
{
strings:
	$a0 = { cd21b44fcd217301c3b80043ba9e00cd21b80143b100cd21b8013dcd2193b440b136ba0001 }


condition:
	$a0
}