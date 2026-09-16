rule Win_Trojan_Hellspawn_1
{
strings:
	$a0 = { e87d0193731db43cb90200ba7f05e86f017215fe06700593b440b97204ba0001e85d01b43e }


condition:
	$a0
}