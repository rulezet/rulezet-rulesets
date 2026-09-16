rule Win_Trojan_RVPS_1
{
strings:
	$a0 = { 5b53b440cd215bb43ecd21 }


condition:
	$a0
}