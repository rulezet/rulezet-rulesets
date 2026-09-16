rule Win_Trojan_Trivial_23
{
strings:
	$a0 = { 4fcd217301c3b443ba9e00cd21b80143b100cd21b8013dcd2193b440b138ba0001cd21b43ecd21 }


condition:
	$a0
}