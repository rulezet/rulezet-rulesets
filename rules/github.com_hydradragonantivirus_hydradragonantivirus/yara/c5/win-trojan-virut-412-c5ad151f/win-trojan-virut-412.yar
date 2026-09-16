rule Win_Trojan_Virut_412
{
strings:
	$a0 = { 86e686e6e80e000000908d3f29d901d99b9b00ee28eef860908b5c2424e9a101 }


condition:
	$a0
}