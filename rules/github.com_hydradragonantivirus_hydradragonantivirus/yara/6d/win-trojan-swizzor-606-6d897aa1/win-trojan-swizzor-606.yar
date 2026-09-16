rule Win_Trojan_Swizzor_606
{
strings:
	$a0 = { 558bec6aff68f0d541006810c4400064a1000000005064 }

	$a1 = { 443a5c434547535146535c43414c59 }


condition:
	$a0 and $a1
}