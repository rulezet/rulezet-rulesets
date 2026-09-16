rule Win_Trojan_Small_149
{
strings:
	$a0 = { 42cdf7b4408d54ff892cb103cdf7b43ecdf71f61ea }


condition:
	$a0
}