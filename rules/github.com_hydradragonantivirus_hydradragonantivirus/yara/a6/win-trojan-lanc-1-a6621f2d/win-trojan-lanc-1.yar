rule Win_Trojan_Lanc_1
{
strings:
	$a0 = { 414e4353504f4c59205355434b4552532e20504f5020 }


condition:
	$a0
}