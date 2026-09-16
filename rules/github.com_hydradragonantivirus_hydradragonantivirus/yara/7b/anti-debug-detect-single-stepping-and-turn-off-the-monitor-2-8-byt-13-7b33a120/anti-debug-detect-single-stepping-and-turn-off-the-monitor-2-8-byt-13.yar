rule anti_debug__Detect_single_stepping_and_turn_off_the_monitor__2___8_byt_13_
{
strings:
	$a0 = { 66bac403b001ee6642ec20d0ee }

condition:
	$a0
}