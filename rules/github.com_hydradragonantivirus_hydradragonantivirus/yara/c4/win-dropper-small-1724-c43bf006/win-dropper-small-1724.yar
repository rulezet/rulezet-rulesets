rule Win_Dropper_Small_1724
{
strings:
	$a0 = { 68000000c06882100010e8??010000 }


condition:
	$a0
}