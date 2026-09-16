rule Win_Trojan_Mini_29
{
strings:
	$a0 = { 83ed0356b41a8bd581c2ae0052cd218bfdb9030083c70987f7f3a45e8bd5b44efcb9ff0083c203cd21730a9090b41a }


condition:
	$a0
}