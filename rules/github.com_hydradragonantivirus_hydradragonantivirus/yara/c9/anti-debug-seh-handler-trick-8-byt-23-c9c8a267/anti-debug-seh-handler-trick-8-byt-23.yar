rule anti_debug__SEH_handler_trick__8_byt_23_
{
strings:
	$a0 = { 5064ff35000000006489250000000033c0c70000010000 }

condition:
	$a0
}