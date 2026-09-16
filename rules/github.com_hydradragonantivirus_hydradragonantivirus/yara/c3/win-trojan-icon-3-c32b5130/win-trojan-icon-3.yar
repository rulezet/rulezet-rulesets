rule Win_Trojan_Icon_3
{
strings:
	$a0 = { 8d960000cd21b440cd21b44fcd21b43cba9e00cd2193b4408d960000cd21b440cd21b44ccd21 }


condition:
	$a0
}