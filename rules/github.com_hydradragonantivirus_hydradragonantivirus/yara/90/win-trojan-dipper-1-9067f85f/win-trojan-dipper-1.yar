rule Win_Trojan_Dipper_1
{
strings:
	$a0 = { cd2172285152b9fd03ba0001b440cd217213b8004233c933d2cd21b91a00b440ba0b01cd21 }


condition:
	$a0
}