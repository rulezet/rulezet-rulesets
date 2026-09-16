rule Win_Trojan_Traveller_2
{
strings:
	$a0 = { 0150c3b045e81d000510002e010609012e01060b01 }


condition:
	$a0
}