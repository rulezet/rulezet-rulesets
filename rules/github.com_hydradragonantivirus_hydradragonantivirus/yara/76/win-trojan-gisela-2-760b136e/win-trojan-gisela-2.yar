rule Win_Trojan_Gisela_2
{
strings:
	$a0 = { b963008e1e4101ba00012eff1e3d01b43e2eff1e3d01 }


condition:
	$a0
}