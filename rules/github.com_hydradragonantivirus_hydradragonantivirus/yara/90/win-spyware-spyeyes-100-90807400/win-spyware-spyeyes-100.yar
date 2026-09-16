rule Win_Spyware_SpyEyes_100
{
strings:
	$a0 = { 495640????????c3 }


condition:
	$a0
}