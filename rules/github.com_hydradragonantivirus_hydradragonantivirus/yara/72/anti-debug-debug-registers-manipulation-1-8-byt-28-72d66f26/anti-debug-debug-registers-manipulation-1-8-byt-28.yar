rule anti_debug__Debug_registers_manipulation__1___8_byt_28_
{
strings:
	$a0 = { 64ff35000000006489250000000031c0f7f0648f050000000083c404 }

condition:
	$a0
}