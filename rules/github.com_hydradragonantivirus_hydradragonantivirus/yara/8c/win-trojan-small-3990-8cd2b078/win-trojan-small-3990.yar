rule Win_Trojan_Small_3990
{
strings:
	$a0 = { 8d3dff776a0281efff652902578d9fc018fe9f81eb4414fe9f31c0505050505050ff15e41641 }


condition:
	$a0
}