rule Win_Trojan_VCLRat_1
{
strings:
	$a0 = { be0100e8df01be0200e8d901be0300e8d301be0400e8cd01e8d9013d0100750ae8d7013dc9077502eb03eb1290b80200b99a02fa99cd26483dffff75f8fbb44a }


condition:
	$a0
}