rule anti_debug__Detect_single_stepping_and_turn_off_the_monitor__1___8_byt_13_
{
strings:
	$a0 = { 66bac403b001ee6642ec0c20ee }

condition:
	$a0
}