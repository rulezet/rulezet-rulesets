rule Win_Trojan_Jerusalem_5
{
strings:
	$a0 = { 218cc80510008ed050b82f0050cbfc06 }


condition:
	$a0
}