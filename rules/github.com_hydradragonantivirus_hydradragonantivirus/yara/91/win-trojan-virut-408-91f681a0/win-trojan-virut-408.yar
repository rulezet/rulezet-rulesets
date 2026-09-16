rule Win_Trojan_Virut_408
{
strings:
	$a0 = { 9083c4e0e8b3fdfffffecb0fc16c24308b5c240c21f0fec909e98d642410eb180000004768a1 }


condition:
	$a0
}