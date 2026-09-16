rule Win_Trojan_Peed_350
{
strings:
	$a0 = { e8a000000068a4b000005981c1508d000081c1a4b0000068????????5e565881 }


condition:
	$a0
}