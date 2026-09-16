rule Win_Trojan_Cruel_4
{
strings:
	$a0 = { fa33c08ed0bc007cfb8ec0b8????bb????b90e00b601b200cd130653cb }


condition:
	$a0
}