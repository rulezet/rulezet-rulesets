rule anti_debug__Popf_and_the_trap_flag__8_byt_9_
{
strings:
	$a0 = { 9cc704e4000100009d }

condition:
	$a0
}