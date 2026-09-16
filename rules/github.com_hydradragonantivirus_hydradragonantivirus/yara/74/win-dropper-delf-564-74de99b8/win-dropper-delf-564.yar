rule Win_Dropper_Delf_564
{
strings:
	$a0 = { b8a02c4000e86bfbffff8bd8a174304000bab02c4000e8beecffff }


condition:
	$a0
}