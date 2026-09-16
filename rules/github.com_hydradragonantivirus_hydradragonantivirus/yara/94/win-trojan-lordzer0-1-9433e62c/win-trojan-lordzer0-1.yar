rule Win_Trojan_Lordzer0_1
{
strings:
	$a0 = { e800005d505181ed0301b8033dba9e00cd21735e8cc98ed98ec18cc1498ec1268b1e0300ba7401b104d3ea83c2048cc1418ec12bdab44acd2172374ab4488bda }


condition:
	$a0
}