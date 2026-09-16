rule Win_Trojan_Oxana_1
{
strings:
	$a0 = { cd218cc88ed82b066802a368028cc03d0000755d }


condition:
	$a0
}