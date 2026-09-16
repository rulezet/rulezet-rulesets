rule Win_Dropper_Delf_622
{
strings:
	$a0 = { 0f84b20000006a006880000000516a0052508d464850e823e7ffff }


condition:
	$a0
}