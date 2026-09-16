rule Win_Trojan_Pixel_17
{
strings:
	$a0 = { 9e00b8023dcd218bd8061fba2b01b9 }


condition:
	$a0
}