rule anti_debug__Rose_s_TRAP__3__8_byt_10_
{
strings:
	$a0 = { b409cd2166b8004ccd21 }

condition:
	$a0
}