rule Win_Trojan_SillyC_238
{
strings:
	$a0 = { fec2b44fe92cffcd2033c933d2b442cd21c300cd20902a2e636f6d00000000002e2e004372617a792e422056697275730d }


condition:
	$a0
}