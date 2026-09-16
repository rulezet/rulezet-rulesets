rule Win_Trojan_Whale_24
{
strings:
	$a0 = { e82f00ff169925ebf7b8020081c361dd }


condition:
	$a0
}