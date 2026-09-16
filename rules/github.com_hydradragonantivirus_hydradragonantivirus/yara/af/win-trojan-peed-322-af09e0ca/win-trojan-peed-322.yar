rule Win_Trojan_Peed_322
{
strings:
	$a0 = { 48b9ee8c0100ba02002002c1ca0b89d652ad05 }


condition:
	$a0
}