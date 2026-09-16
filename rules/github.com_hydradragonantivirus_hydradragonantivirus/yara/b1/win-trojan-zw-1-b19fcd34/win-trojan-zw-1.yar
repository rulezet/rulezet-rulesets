rule Win_Trojan_ZW_1
{
strings:
	$a0 = { c00510008ed88c06ad078ccb432bc3cd21e8fa00c3585b595afa8cd28cc88ed0bc001ffb518ed92e890eb3070e07be }


condition:
	$a0
}