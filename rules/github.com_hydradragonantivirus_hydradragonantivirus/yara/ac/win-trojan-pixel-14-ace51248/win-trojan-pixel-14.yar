rule Win_Trojan_Pixel_14
{
strings:
	$a0 = { b90101f3a4ba0501b90600b44ecd2172 }


condition:
	$a0
}