rule Win_Trojan_Cfsk_2
{
strings:
	$a0 = { 04b440ba4004b90500cd21722ce824ffa34e04e84900b995044181e90001b440ba0001cd2172 }


condition:
	$a0
}