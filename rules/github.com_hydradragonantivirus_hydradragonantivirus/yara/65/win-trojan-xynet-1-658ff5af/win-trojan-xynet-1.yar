rule Win_Trojan_Xynet_1
{
strings:
	$a0 = { 8f03be240003f5b80135cd21268a07bb21133014301c300446e2ec }


condition:
	$a0
}