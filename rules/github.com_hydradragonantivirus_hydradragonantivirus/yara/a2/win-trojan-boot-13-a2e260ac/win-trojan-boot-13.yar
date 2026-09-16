rule Win_Trojan_Boot_13
{
strings:
	$a0 = { 07bfbe07b920002e8b042e890583c60283c702e2f2b80103ba8000b90100bb0006cd13b80102 }


condition:
	$a0
}