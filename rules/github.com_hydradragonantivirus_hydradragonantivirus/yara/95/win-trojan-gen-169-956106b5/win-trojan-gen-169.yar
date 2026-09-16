rule Win_Trojan_Gen_169
{
strings:
	$a0 = { d30150b8c80050e808155959a33d018b1e3d01ff077d138b1e3d018b7f0aff470aa03b018805b4 }


condition:
	$a0
}