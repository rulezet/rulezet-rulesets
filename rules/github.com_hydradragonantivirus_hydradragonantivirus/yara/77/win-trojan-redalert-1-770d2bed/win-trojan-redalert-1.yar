rule Win_Trojan_RedAlert_1
{
strings:
	$a0 = { b5b1b6b2cd21b42bb9d007b601b201cd21b44ccd21496e666563746564206279205265642041 }


condition:
	$a0
}