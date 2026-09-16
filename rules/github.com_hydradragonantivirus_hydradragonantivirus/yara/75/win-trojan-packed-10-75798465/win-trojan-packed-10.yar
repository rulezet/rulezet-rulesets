rule Win_Trojan_Packed_10
{
strings:
	$a0 = { 807c240801565058eb[0-30]9a0f85 }


condition:
	$a0
}