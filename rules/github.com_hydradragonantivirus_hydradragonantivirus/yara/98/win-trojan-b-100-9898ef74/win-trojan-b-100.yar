rule Win_Trojan_B_100
{
strings:
	$a0 = { 1e4301730c33c09c2eff1e43014f75ebf9c3be3e00bf3e02b96801fcf3a4 }


condition:
	$a0
}