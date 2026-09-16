rule anti_debug__Rose_s_TRAP__1__8_byt_46_
{
strings:
	$a0 = { 668cca6631db6689d98ec3fa6726668707672666875702fb66f7f166b8004ccd21fa6726668707672666875702fb }

condition:
	$a0
}