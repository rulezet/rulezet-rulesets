rule Win_Trojan_Pixel_30
{
strings:
	$a0 = { 01b90600b44ecd217260ba8202b802 }


condition:
	$a0
}