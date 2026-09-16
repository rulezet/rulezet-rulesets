rule Win_Trojan_Whale_25
{
strings:
	$a0 = { 2e0059ff169825ebf6b8020081c361 }


condition:
	$a0
}