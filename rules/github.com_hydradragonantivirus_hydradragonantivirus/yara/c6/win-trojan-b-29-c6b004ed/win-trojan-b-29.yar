rule Win_Trojan_B_29
{
strings:
	$a0 = { c08ed0bc007cfb8ec0b80102bb007eb90e00b601b200cd130653cb }


condition:
	$a0
}