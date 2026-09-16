rule anti_debug__Detect_SoftICE_VxD_or_SoftICE_GFX_VxD__8_byt_25_
{
strings:
	$a0 = { 6631ff8ec766b8841666bb0202cd2f668cc06601c76683ff00 }

condition:
	$a0
}