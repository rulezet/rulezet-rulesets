rule Win_Trojan_Trivial_25
{
strings:
	$a0 = { 3601cd21eb0890b44fcd217301c3b443ba9e00cd21b80143b100cd21b8013dcd2193b440b13a90 }


condition:
	$a0
}