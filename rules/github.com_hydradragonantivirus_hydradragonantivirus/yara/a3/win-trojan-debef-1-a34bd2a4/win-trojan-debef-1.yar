rule Win_Trojan_Debef_1
{
strings:
	$a0 = { 8ab611010af65a740232f232e62e882743fec2e2e6c358 }


condition:
	$a0
}