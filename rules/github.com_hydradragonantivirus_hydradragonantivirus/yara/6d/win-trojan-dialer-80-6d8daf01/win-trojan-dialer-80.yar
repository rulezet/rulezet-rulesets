rule Win_Trojan_Dialer_80
{
strings:
	$a0 = { af13a197f5573285b7305374617264402eb04bf465723300ed2eea2391da000a25735c02f7fcdf97202e6c6e6b174465 }


condition:
	$a0
}