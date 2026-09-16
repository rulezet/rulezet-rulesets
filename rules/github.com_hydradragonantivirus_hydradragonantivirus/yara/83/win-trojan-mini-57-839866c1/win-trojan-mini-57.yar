rule Win_Trojan_Mini_57
{
strings:
	$a0 = { cd2193b43f5459ba3d01cd2180bc3d002a7412fec45033c9f7e1b442cd2189f259b440cd21b4 }


condition:
	$a0
}