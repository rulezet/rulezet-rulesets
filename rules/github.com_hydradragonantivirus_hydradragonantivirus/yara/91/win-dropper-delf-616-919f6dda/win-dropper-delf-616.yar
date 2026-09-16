rule Win_Dropper_Delf_616
{
strings:
	$a0 = { 5188f1516a0088d15166ba00005250e893faffffc3 }


condition:
	$a0
}