rule Win_Trojan_AWVCK_1
{
strings:
	$a0 = { 24833e9c00007517ba9e00b8013dcd2193b440ba0001b99c00cd21b43ecd21b44fcd2173dac3 }


condition:
	$a0
}