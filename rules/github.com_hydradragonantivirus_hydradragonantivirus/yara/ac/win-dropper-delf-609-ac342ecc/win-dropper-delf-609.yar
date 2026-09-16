rule Win_Dropper_Delf_609
{
strings:
	$a0 = { 0f84b20000006a006880000000516a0052508d464850e847e7ffff83f8ff0f8408010000 }


condition:
	$a0
}