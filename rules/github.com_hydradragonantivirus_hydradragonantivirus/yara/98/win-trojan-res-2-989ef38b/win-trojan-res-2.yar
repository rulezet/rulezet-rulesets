rule Win_Trojan_Res_2
{
strings:
	$a0 = { 8ee366c2207e5c8c01d154f1c799bbe23da0fea1f9f4124a167ad235633daee3cf65f0 }


condition:
	$a0
}