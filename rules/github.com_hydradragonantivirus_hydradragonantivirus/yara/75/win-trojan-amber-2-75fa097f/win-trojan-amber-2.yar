rule Win_Trojan_Amber_2
{
strings:
	$a0 = { 9107928a1a1a1a3ed943ab8a1a1a1a44788c8d5f58acfd8d73f58b1a0bc8248b42961a1afce80bc8 }


condition:
	$a0
}