rule Win_Trojan_Fish6_1
{
strings:
	$a0 = { e800005b81eba90db9580d2e8037 }


condition:
	$a0
}