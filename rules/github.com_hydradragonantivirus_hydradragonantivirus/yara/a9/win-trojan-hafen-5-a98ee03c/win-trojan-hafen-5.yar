rule Win_Trojan_Hafen_5
{
strings:
	$a0 = { 038d940001b440cd218b9c1904b9 }


condition:
	$a0
}