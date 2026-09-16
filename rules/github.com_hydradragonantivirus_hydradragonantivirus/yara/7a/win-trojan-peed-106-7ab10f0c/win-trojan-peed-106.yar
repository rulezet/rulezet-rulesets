rule Win_Trojan_Peed_106
{
strings:
	$a0 = { 6bc900e80a000000f7d029c74f4029c6eb235a8d1d }


condition:
	$a0
}