rule Win_Trojan_Mini_69
{
strings:
	$a0 = { 9e00cd2193b43f8bd68bcccd21803c80741405530090502bc9f7e1b442cd2159b4405a52cd21b4 }


condition:
	$a0
}