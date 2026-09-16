rule anti_debug__PEB_IsDebugged__8_byt_12_
{
strings:
	$a0 = { 64a1300000000fb6400285c0 }

condition:
	$a0
}