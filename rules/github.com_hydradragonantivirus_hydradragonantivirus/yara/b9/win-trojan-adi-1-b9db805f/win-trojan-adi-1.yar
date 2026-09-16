rule Win_Trojan_ADI_1
{
strings:
	$a0 = { 01b44ecd21e440a801741cba9e00b43cb92000cd2193720fb440ba0001b92c0690cd21b43ecd }


condition:
	$a0
}