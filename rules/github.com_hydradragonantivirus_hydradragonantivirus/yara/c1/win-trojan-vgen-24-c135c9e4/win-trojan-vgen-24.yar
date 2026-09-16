rule Win_Trojan_VGEN_24
{
strings:
	$a0 = { b80635cd21b425cd218dd3061fcd21b44ccd215a5a8bd3601ebf03008b6d13061fcd214d8edd458b3533db8edb }


condition:
	$a0
}