rule Win_Trojan_Dikshev_34
{
strings:
	$a0 = { 9e00bf3d0157acaa3c0074093c2e75f6be3901ebf15ab45bcd21720993b440ba3d009087d1ebd3 }


condition:
	$a0
}