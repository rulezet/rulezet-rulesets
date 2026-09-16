rule Win_Trojan_Iotm_1
{
strings:
	$a0 = { cd21b440ba0001b9f103cd21b8024233c98bd1cd218bce8bd1be05058bfeacd0c0d0c0d0c0aa }


condition:
	$a0
}