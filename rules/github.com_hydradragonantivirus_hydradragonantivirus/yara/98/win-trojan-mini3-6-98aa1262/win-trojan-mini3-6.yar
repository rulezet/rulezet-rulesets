rule Win_Trojan_Mini3_6
{
strings:
	$a0 = { 80fc4390743680fc56743180fc6c742c80fc4174273d38f075049d33c0cf80fc1a750a2e8916 }


condition:
	$a0
}