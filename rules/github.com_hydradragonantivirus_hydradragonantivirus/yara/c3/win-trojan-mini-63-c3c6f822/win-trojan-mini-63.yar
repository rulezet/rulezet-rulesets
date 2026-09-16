rule Win_Trojan_Mini_63
{
strings:
	$a0 = { cd2193b43f5459ba4e01cd213854547412fec45033c9f7e1b442cd2189f259b440cd21b44feb }


condition:
	$a0
}