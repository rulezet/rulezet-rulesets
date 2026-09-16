rule Win_Trojan_Mini_72
{
strings:
	$a0 = { ba9e00cd2193b43f8bd65459cd21803cfe741405560090502bc9f7e1b442cd2159b4405a52 }


condition:
	$a0
}