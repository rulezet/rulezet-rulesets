rule Win_Trojan_Trivial_16
{
strings:
	$a0 = { 43ba9e00cd21b443b001b100cd21b8013dcd2193b440b135ba0001cd21b43ecd21b44febd42a }


condition:
	$a0
}