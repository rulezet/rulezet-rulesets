rule Win_Trojan_VCL_10
{
strings:
	$a0 = { 72bc2d03008984380ab8024233c933d2cd217303e9ae00b440b9b0098d940301e838fccd21 }


condition:
	$a0
}