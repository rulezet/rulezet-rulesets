rule Win_Trojan_Pixel_22
{
strings:
	$a0 = { 01b90600b44ecd217258ba9e00b802 }


condition:
	$a0
}