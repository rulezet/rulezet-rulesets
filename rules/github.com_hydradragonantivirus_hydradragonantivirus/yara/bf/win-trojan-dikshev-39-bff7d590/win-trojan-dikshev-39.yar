rule Win_Trojan_Dikshev_39
{
strings:
	$a0 = { 430157acaa3c0074093c2e75f6be3f01ebf15ab45bb90001cd21720a93b440ba430087d1cd21b4 }


condition:
	$a0
}