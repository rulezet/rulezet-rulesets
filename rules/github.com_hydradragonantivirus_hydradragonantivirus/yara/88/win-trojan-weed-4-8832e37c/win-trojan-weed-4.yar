rule Win_Trojan_Weed_4
{
strings:
	$a0 = { 055f5ad981009db9fd36d04f0c4de89b050febe020cedc }


condition:
	$a0
}