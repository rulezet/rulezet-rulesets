rule Win_Trojan_WillyWorm_1
{
strings:
	$a0 = { 8bec836e02038b6e022ec74600fc8c2ec64602c82ec706000000005de8cc01558bece8b701e824000e1fbe0001b900 }


condition:
	$a0
}