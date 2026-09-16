rule Win_Trojan_Platinum_1
{
strings:
	$a0 = { 8c06b7002e8c06f0042e8c06b4042e8c069e042e8c06a2 }


condition:
	$a0
}