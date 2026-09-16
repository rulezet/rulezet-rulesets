rule Win_Trojan_VS_9
{
strings:
	$a0 = { 0356b104d3ee83ee108cd803c68ed85eb8aaaacd213deeee74468cc8488ec0bb030026812f29004b2e8b072d29 }


condition:
	$a0
}