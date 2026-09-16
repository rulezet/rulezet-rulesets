rule Win_Dropper_Small_1910
{
strings:
	$a0 = { b8001040008030??8000??403db44040007ef2e90dfeffff }


condition:
	$a0
}