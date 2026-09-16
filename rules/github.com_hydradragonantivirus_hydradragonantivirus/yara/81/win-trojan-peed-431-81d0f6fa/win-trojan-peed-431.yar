rule Win_Trojan_Peed_431
{
strings:
	$a0 = { 83c0050bd741534a83e2958bde03c1574b81e70d8a733a8bd803c75683c16a81cbaa }


condition:
	$a0
}