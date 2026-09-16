rule Win_Trojan_AD_4
{
strings:
	$a0 = { 8a660fcd21595a5832c0cd218bd7b0e9aa8b441a2d0300abb0adaa8bfab1048a660fcd21eb }


condition:
	$a0
}