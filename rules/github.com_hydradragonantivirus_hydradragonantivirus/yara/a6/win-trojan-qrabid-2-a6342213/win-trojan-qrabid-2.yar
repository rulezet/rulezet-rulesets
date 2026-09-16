rule Win_Trojan_QRabid_2
{
strings:
	$a0 = { ebed0000565633c050b832005033c050e8810083c4085633c050b8320050b8010050e86f00 }


condition:
	$a0
}