rule Win_Trojan_DustySky_27
{
strings:
	$a0 = { 7a796d32303034323130353033315f4c69622e657865 }


condition:
	$a0
}