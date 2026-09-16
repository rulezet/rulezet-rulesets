rule Win_Trojan_Delf_412
{
strings:
	$a0 = { 4000e819c4ffffff75b4683c754000b8a0860100e807b7ffff8d55b0e867dcffffff75b08d45ecba03000000e8f7c4ffff6a006a008b45e8e82bc6ff }


condition:
	$a0
}