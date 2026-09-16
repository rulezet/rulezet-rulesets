rule Win_Trojan_Mini3_5
{
strings:
	$a0 = { 743680fc56743180fc6c742c80fc4174273d37f075049d33c0cf80fc1a750a2e891620022e }


condition:
	$a0
}