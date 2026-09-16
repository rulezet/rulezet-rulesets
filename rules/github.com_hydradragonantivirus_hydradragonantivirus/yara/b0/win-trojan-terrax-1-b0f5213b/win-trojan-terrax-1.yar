rule Win_Trojan_TerraX_1
{
strings:
	$a0 = { 8c5c0a8c5c0e8c5c12b404cd1a80fa187538525ae54025030301c2e54025030329c25280fe1277eb80fa2c77e6 }


condition:
	$a0
}