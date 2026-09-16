rule Win_Dropper_Small_1957
{
strings:
	$a0 = { 595768800000006a03576a0189460868000000808d85b0feffff50ffd3 }


condition:
	$a0
}