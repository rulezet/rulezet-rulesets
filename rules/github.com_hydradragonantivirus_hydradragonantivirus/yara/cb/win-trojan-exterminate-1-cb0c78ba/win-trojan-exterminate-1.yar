rule Win_Trojan_Exterminate_1
{
strings:
	$a0 = { 1e06eb16905153bb180033c1b92600320743e2fb5b59c3 }


condition:
	$a0
}