rule Win_Trojan_Trivial_15
{
strings:
	$a0 = { ba9e00cd21b80143b100cd21b8013dcd2193b440b134ba0001cd21b43ecd21b44febd52a2e }


condition:
	$a0
}