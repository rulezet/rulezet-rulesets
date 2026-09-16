rule Win_Trojan_Pixel_28
{
strings:
	$a0 = { b44ecd217260ba7d02b8023dcd21 }


condition:
	$a0
}