rule Win_Trojan_Peed_411
{
strings:
	$a0 = { eb2cb983bf5e0e81e90dbb5e0e83c0ffba10000011c1c212 }


condition:
	$a0
}