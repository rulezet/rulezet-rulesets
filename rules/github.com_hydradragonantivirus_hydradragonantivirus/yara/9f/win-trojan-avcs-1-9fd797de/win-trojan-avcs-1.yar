rule Win_Trojan_AVCS_1
{
strings:
	$a0 = { b60901bfbef9b90b01f3a4bee2f9e85bffb440babef9b90b01cd21b80042e81c00b440b903 }


condition:
	$a0
}