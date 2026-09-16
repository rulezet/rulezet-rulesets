rule Win_Trojan_VGEN_233
{
strings:
	$a0 = { bb7201810730374343e2f8b8c9d02551b6e4c95d7f92ca8fc9d11f756d964f89cbd17cea556657d295f1556625 }


condition:
	$a0
}