rule Win_Trojan_Mybot_7678
{
strings:
	$a0 = { bf1752c63329e7536d038067bd4156bb7183ffff534849454c44bfe5fd0352000bc80b62 }


condition:
	$a0
}