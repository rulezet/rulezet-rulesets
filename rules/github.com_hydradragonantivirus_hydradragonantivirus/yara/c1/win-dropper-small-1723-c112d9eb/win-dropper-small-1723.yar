rule Win_Dropper_Small_1723
{
strings:
	$a0 = { 68000000c06882100010e8db010000 }


condition:
	$a0
}