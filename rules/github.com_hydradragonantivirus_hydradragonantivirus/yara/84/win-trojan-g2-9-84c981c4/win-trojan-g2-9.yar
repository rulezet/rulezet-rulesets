rule Win_Trojan_G2_9
{
strings:
	$a0 = { cd2180fe06751a80fa0c7515b4098d96b302cd21b002b9e613fa99cd26fbe80100c35d81ed2401061e0e1f0e078d }


condition:
	$a0
}