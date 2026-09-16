rule Win_Trojan_Bancos_1861
{
strings:
	$a0 = { 8b486062ebbd54c1bc721b4633aaede9ff6f1bf03942f1e858b70c7d58f8a218989762c09e8e77dc1cd6c6e988ac32b40679c546fc35360eda46a744ee8a667130f3b019a79f }


condition:
	$a0
}