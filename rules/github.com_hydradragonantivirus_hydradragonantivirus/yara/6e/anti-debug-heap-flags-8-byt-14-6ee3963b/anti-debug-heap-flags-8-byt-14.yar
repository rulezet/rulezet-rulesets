rule anti_debug__Heap_flags__8_byt_14_
{
strings:
	$a0 = { 64a1300000008b40188b401085c0 }

condition:
	$a0
}