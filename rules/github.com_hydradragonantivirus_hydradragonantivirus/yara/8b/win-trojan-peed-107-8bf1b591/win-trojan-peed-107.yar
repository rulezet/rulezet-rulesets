rule Win_Trojan_Peed_107
{
strings:
	$a0 = { e80000000029d287d15a8d1dfc??400029d2528b3b89e353ffd769c900010000 }


condition:
	$a0
}