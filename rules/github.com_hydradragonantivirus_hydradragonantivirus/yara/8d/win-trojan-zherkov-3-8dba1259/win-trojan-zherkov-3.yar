rule Win_Trojan_Zherkov_3
{
strings:
	$a0 = { 2e8a44f83c00740f83c61890b9fa062e3004fec046e2f8 }


condition:
	$a0
}