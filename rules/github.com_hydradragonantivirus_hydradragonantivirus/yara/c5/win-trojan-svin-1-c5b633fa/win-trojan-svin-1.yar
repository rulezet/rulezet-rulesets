rule Win_Trojan_Svin_1
{
strings:
	$a0 = { f3a4be84008ed9a5a5c744fc5500c744fe60001f07c3 }


condition:
	$a0
}