rule Win_Trojan_Trivial_26
{
strings:
	$a0 = { cd21eb0890b44fcd217301c3b80043ba9e00cd21b80143b100cd21b8013dcd2193b440b13b }


condition:
	$a0
}